const fs = require("fs");
const path = require("path");

function download(req, res) {
  const target = path.join("/var/data", req.query.name);
  return fs.createReadStream(target).pipe(res);
}
