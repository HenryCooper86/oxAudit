export function Label({ secret }: { secret: boolean }) {
  return <span>{secret ? "Secret" : "Vulnerability"}</span>;
}
