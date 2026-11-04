import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { Field } from "./Field";
import { Input } from "../ui";

test("associates hints and errors without dropping caller descriptions, then clears invalid state", () => {
  const view = (error?: string) => <><p id="external-help">External help</p>
    <Field label="Expiry" htmlFor="expiry" hint="Choose a future date" error={error}>
      <Input id="expiry" aria-describedby="external-help expiry-hint" />
    </Field></>;
  const { rerender } = render(view("Expiry must be in the future"));
  const control = screen.getByLabelText("Expiry");
  expect(control).toHaveAttribute("aria-invalid", "true");
  expect(control).toHaveAccessibleDescription("External help Choose a future date Expiry must be in the future");
  rerender(view());
  expect(control).not.toHaveAttribute("aria-invalid", "true");
  expect(control).toHaveAccessibleDescription("External help Choose a future date");
});

test("does not attach a field error to an unrelated child", () => {
  render(<Field label="Target" htmlFor="target" error="Required">
    <Input id="other" aria-label="Other control" aria-describedby="own-help" aria-invalid="true" />
  </Field>);
  expect(screen.getByLabelText("Other control")).toHaveAttribute("aria-describedby", "own-help");
  expect(screen.getByLabelText("Other control")).toHaveAttribute("aria-invalid", "true");
});
