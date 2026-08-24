// A method called `eval` on a maths library is not the global eval sink.
const result = expressionParser.eval("2 + 2");

// Nor is a property whose name merely contains the word.
const config = { evaluation: true, reevaluate: false };
