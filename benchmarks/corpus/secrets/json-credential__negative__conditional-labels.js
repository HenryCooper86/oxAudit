export function family(path) {
  return path.includes("/secrets/") ? "secret" : "source-pattern";
}
