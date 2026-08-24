// A string literal cannot be attacker controlled. Reporting this teaches a
// reviewer that the rule does not know what it is looking at.
export function arithmetic() {
  return eval("2 + 2");
}

export function templateWithNoInterpolation() {
  return eval(`1 + 1`);
}
