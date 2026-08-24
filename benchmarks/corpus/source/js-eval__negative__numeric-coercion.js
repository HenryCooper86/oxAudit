export function evaluateIndex(userInput) {
  // parseInt cannot return anything but a number, so nothing an attacker
  // writes survives into the sink.
  return eval(parseInt(userInput, 10));
}
