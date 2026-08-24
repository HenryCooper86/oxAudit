export function render(userInput) {
  // A parameter is reachable by whatever calls this.
  return eval(userInput);
}
