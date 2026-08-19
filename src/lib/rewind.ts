/**
 * Rewinding a conversation to an earlier user turn.
 *
 * The plan is computed as pure data so the destructive part — truncating the
 * persisted transcript — is decided by something testable rather than by
 * arithmetic scattered through a click handler.
 */

export interface RewindTarget {
  id: string;
  role: "user" | "assistant";
  content: string;
}

export interface RewindPlan {
  /** Messages to keep, i.e. everything strictly before the target. */
  keepCount: number;
  /** The target's text, handed back to the composer so it can be re-asked. */
  restoredInput: string;
  /** How many messages the rewind discards; used for the confirmation copy. */
  discardedCount: number;
}

/**
 * Plan a rewind to `messageId`.
 *
 * Returns `null` when the rewind would be meaningless or unsafe: an unknown id,
 * an assistant turn (rewinding to the model's own output would leave a dangling
 * question), or a target that is already the last thing in the conversation
 * with nothing after it to discard.
 */
export function planRewind(
  messages: readonly RewindTarget[],
  messageId: string,
): RewindPlan | null {
  const index = messages.findIndex((message) => message.id === messageId);
  if (index === -1) return null;

  const target = messages[index];
  if (target.role !== "user") return null;

  const discardedCount = messages.length - index;
  if (discardedCount <= 0) return null;

  return {
    keepCount: index,
    restoredInput: target.content,
    discardedCount,
  };
}
