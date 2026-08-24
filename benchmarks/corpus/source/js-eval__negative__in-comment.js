// Never call eval(userInput) here — it was removed in #412 because the argument
// is attacker controlled.
function render(userInput) {
  return template(userInput);
}
