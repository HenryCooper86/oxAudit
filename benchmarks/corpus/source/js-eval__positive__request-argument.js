export function handler(req, res) {
  const expression = req.body.expression;
  res.send(eval(expression));
}
