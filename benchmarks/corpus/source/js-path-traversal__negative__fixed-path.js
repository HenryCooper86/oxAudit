const fs = require("fs");

function readConfig() {
  // A path with nothing concatenated into it cannot traverse.
  return fs.readFileSync("/etc/oxaudit/config.json", "utf8");
}
