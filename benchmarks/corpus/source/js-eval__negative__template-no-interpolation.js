export function fixedExpression() {
  // A template literal with nothing substituted in is just a string.
  return eval(`2 + 2`);
}
