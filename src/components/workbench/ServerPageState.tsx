import { InlineState } from "./InlineState";
import { Button } from "../ui";
export function ServerPageState({ page }: { page: { loading: boolean; error: string | null; retry(): void } }) {
  return page.loading ? <InlineState tone="running" compact title="Loading saved results" />
    : page.error ? <InlineState tone="error" compact title="Saved results unavailable" description={page.error} action={<Button variant="outline" onClick={page.retry}>Retry page</Button>} /> : null;
}
