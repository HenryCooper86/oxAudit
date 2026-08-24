import { escapeHtml } from "./escape";

export function render(userInput) {
  // escapeHtml neutralizes markup. It does nothing whatsoever about code
  // execution, so this is still a live RCE and must still be reported.
  return eval(escapeHtml(userInput));
}
