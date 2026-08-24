const EXPRESSION = "1 + 1";

export function evaluateConstant() {
  // The identifier resolves to a literal in the same scope.
  return eval(EXPRESSION);
}
