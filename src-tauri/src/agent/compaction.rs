//! Context compaction: when a conversation no longer fits the configured
//! context window, summarize the older turns into a single dense summary and
//! keep the newest turns verbatim, instead of failing the request.
//!
//! The split is computed as pure data (`plan_compaction`), the summary is
//! produced by one non-streaming model call (`summarize_messages`), and the
//! replacement message list is assembled by `apply`. Keeping the three separate
//! makes the boundary logic unit-testable without a live model.

use serde_json::{json, Value};

use crate::ai::AiClient;
use crate::credentials::ResolvedAiSettings;
use crate::models::{ChatMessage, ChatRequest};

/// Share of the context window the *kept* slice may occupy (system prompt +
/// tools + reserved output + retained turns). The remainder is headroom for the
/// summary itself and for tool results the model generates during the turn.
const KEPT_RATIO_NUMERATOR: u64 = 2;
const KEPT_RATIO_DENOMINATOR: u64 = 3;

/// Cap on the summary length. Half a conversation should compress into far less
/// than this, and a bounded summary keeps the compacted request comfortably
/// inside the headroom left by `KEPT_RATIO_*`.
const SUMMARY_MAX_TOKENS: u32 = 1024;

/// Which messages to fold and which to keep, decided by `plan_compaction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadSelection {
    /// Index into the input `messages` of the first message to keep verbatim.
    /// `messages[0]` (the system prompt) is always kept; `messages[1..keep_from]`
    /// is summarized.
    pub keep_from: usize,
    /// Number of history messages folded into the summary.
    pub summarized: usize,
}

/// Decide whether compaction is needed and, if so, where to cut.
///
/// `messages` is the full request as the loop sees it: `[system, ...history]`.
/// `reserved` is the output budget (`max_tokens`) that must stay available.
///
/// Returns `None` when the conversation fits or there is no history to fold.
pub fn plan_compaction(
    messages: &[Value],
    tools: &[Value],
    context_window: u32,
    reserved: u32,
) -> Option<HeadSelection> {
    // `[system, current]` is already the minimum; there is nothing to fold.
    if messages.len() <= 2 {
        return None;
    }
    // Already fits — nothing to do.
    if AiClient::estimate_context_tokens(messages, tools).saturating_add(reserved) <= context_window
    {
        return None;
    }

    let target =
        (u64::from(context_window) * KEPT_RATIO_NUMERATOR / KEPT_RATIO_DENOMINATOR).max(1) as u32;

    // Walk from the newest message backwards, keeping turns while the kept
    // slice (system + retained turns + tools + reserved output) fits the target.
    let mut kept = 0usize;
    let mut running =
        AiClient::estimate_context_tokens(&messages[..1], tools).saturating_add(reserved);
    for message in messages[1..].iter().rev() {
        let cost = AiClient::estimate_context_tokens(std::slice::from_ref(message), &[]);
        if running.saturating_add(cost) > target {
            break;
        }
        running = running.saturating_add(cost);
        kept += 1;
    }
    // Always retain at least the newest turn — the question being answered.
    kept = kept.max(1);

    let keep_from = messages.len() - kept;
    let summarized = keep_from.saturating_sub(1);
    if summarized == 0 {
        return None;
    }
    Some(HeadSelection {
        keep_from,
        summarized,
    })
}

/// Reassemble the message list with `messages[1..keep_from]` replaced by a
/// single system-role summary, preserving the original system prompt at index 0.
pub fn apply(messages: &[Value], keep_from: usize, summary: &str) -> Vec<Value> {
    debug_assert!(keep_from > 1 && keep_from < messages.len());
    let mut out = Vec::with_capacity(2 + (messages.len() - keep_from));
    out.push(messages[0].clone());
    out.push(json!({
        "role": "system",
        "content": format!(
            "Earlier in this conversation, summarized to fit the context window:\n{summary}"
        ),
    }));
    out.extend_from_slice(&messages[keep_from..]);
    out
}

/// Produce a one-message summary of the given history turns via a single
/// non-streaming model call. `messages` is the history only (no system prompt).
pub async fn summarize_messages(
    client: &AiClient,
    settings: &ResolvedAiSettings,
    messages: &[Value],
) -> Result<String, String> {
    let transcript = messages
        .iter()
        .map(|message| {
            let role = message
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("message");
            let content = message.get("content").and_then(Value::as_str).unwrap_or("");
            format!("[{role}]\n{content}")
        })
        .collect::<Vec<_>>()
        .join("\n\n");

    let system =
        "You are condensing part of a security research conversation so it fits a context window. \
Summarize the transcript below, preserving every concrete fact a reviewer still needs: \
specific findings (rule, file path, line, CWE, severity), CVE IDs, affected packages and versions, \
evidence already gathered from tools, conclusions reached, and anything left open. \
Omit pleasantries, repetition, and anything the rest of the conversation already implies. \
Keep it dense and factual; do not invent facts that are not in the transcript.";

    let response = client
        .chat(
            settings,
            ChatRequest {
                messages: vec![
                    ChatMessage {
                        role: "system".into(),
                        content: system.into(),
                    },
                    ChatMessage {
                        role: "user".into(),
                        content: transcript,
                    },
                ],
                temperature: Some(0.0),
                max_tokens: Some(SUMMARY_MAX_TOKENS),
                conversation_id: None,
                allow_compaction: true,
            },
        )
        .await?;

    let summary = response.content.trim().to_string();
    if summary.is_empty() {
        return Err("summarization produced an empty result".into());
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system(content: &str) -> Value {
        json!({ "role": "system", "content": content })
    }

    fn user(content: &str) -> Value {
        json!({ "role": "user", "content": content })
    }

    fn assistant(content: &str) -> Value {
        json!({ "role": "assistant", "content": content })
    }

    /// A message whose estimated cost is large enough to move a small window.
    fn heavy(content: &str) -> Value {
        user(&content.repeat(400))
    }

    #[test]
    fn a_conversation_with_no_history_never_compacts() {
        let messages = vec![system("prompt"), user("hello")];
        assert_eq!(plan_compaction(&messages, &[], 100, 0), None);
    }

    #[test]
    fn a_fitting_conversation_is_left_alone() {
        let messages = vec![system("prompt"), user("a"), assistant("b")];
        assert_eq!(plan_compaction(&messages, &[], 10_000, 0), None);
    }

    #[test]
    fn an_oversized_conversation_folds_the_head_and_keeps_the_newest_turn() {
        let messages = vec![
            system("prompt"),
            heavy("first"),
            heavy("second"),
            heavy("third"),
            heavy("fourth"),
            user("the current question"),
        ];
        // Full conversation far exceeds a 300-token window.
        assert!(AiClient::estimate_context_tokens(&messages, &[]) > 300);

        let plan = plan_compaction(&messages, &[], 300, 0).expect("must compact");

        // The newest turn is kept; the four older turns are folded.
        assert_eq!(plan.keep_from, messages.len() - 1);
        assert_eq!(plan.summarized, 4);
    }

    #[test]
    fn reserved_output_tokens_can_force_a_compaction_the_input_otherwise_fits() {
        let messages = vec![
            system("prompt"),
            user("the first question, quite short"),
            user("the current question"),
        ];
        let tools = Vec::new();
        // Pick a window exactly big enough for the input: with no reserve it
        // fits, and any positive reserve for the reply forces a compaction.
        let window = AiClient::estimate_context_tokens(&messages, &tools);
        assert_eq!(plan_compaction(&messages, &tools, window, 0), None);

        let plan =
            plan_compaction(&messages, &tools, window, 1).expect("reserve forces compaction");
        assert_eq!(plan.summarized, 1);
        assert_eq!(plan.keep_from, messages.len() - 1);
    }

    #[test]
    fn apply_keeps_the_system_prompt_and_places_the_summary_before_the_tail() {
        let messages = vec![
            system("prompt"),
            user("old a"),
            assistant("old b"),
            user("new question"),
        ];
        // Fold `messages[1..3]` ("old a", "old b") and keep the newest turn.
        let applied = apply(&messages, 3, "condensed");

        assert_eq!(applied.len(), 3);
        assert_eq!(applied[0]["role"], "system");
        assert_eq!(applied[0]["content"], "prompt");
        assert_eq!(applied[1]["role"], "system");
        assert!(
            applied[1]["content"]
                .as_str()
                .unwrap()
                .contains("condensed"),
            "the summary must be labelled so the model reads it as context"
        );
        assert_eq!(applied[2]["content"], "new question");
    }
}
