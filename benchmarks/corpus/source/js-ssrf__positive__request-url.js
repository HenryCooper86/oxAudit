async function proxy(req) {
  // The destination comes from the request, so the server can be pointed at
  // anything reachable from it, including its own metadata service.
  return fetch(req.query.target);
}
