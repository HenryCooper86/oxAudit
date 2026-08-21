# Assistant redesign QA

Date: 2026-08-21

## Visual target

- Reference: y-agent's committed dark GUI screenshot at 1280 × 890.
- Implementation: oxAudit Assistant captured at the same 1280 × 890 viewport.
- Comparison image: `/tmp/oxaudit-assistant-audit/10-selected-comparison.png`.

The reference shows a populated native conversation, while the browser preview
shows oxAudit's empty and AI-unavailable state because Tauri commands are not
available in a regular browser. The shell, hierarchy, composer, activity rail,
empty state, and responsive behavior are directly comparable. Populated message
rendering was additionally checked through the component source, TypeScript,
and the existing automated suite.

## QA results

| Area | Result | Notes |
| --- | --- | --- |
| Information hierarchy | Pass | Conversation title, readiness, transcript, composer, and activity now have distinct regions. |
| Conversation density | Pass | Assistant prose is unboxed; user turns remain compact and visually directional. |
| Composer | Pass | The input and toolbar form one 8 px floating surface with context, readiness, usage, send, steer, and cancel controls. |
| Operational feedback | Pass | Plan, tools, tokens, cost, model, and running state live in a dedicated optional rail. |
| Session navigation | Pass | New-chat and search actions share a compact header; selected sessions retain a clear state. |
| Shell proportions | Pass | Assistant mode collapses the global navigation to a 52 px icon rail, preserving the product map without competing with sessions or conversation space. |
| Responsive behavior | Pass | At 1024 × 768 the activity rail hides while sessions and the composer remain usable. |
| Accessibility | Pass | Named regions, headings, dialog labels, status text, focus styles, and button labels remain available. |
| Console | Pass | A fresh browser load produced no warnings or errors. |

## Issues resolved during QA

- Replaced full-card assistant bubbles with a readable continuous transcript.
- Reduced tool calls and reasoning from heavy cards to compact expandable rows.
- Moved context and send controls into the composer toolbar.
- Added the activity rail and a working show/hide control.
- Added a compact-session search toggle and verified its focus behavior.
- Collapsed the global sidebar to a tooltip-backed icon rail in Assistant mode.
- Verified the context dialog opens and closes from the new toolbar.

## Follow-up polish

- P3: capture one populated native conversation in a future visual regression
  fixture so answer, tool, and reasoning states can be compared without a live
  provider.

final result: passed
