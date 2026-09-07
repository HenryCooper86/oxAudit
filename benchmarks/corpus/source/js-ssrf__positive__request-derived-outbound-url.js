export async function preview(req) {
  const url = req.query.previewUrl;
  return fetch(url);
}
