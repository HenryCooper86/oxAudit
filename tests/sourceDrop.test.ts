import assert from "node:assert/strict";
import test from "node:test";
import { chooseDroppedPath } from "../src/features/source-scan/useProjectDrop";

test("a dropped path list selects exactly the first path", () => {
  assert.equal(
    chooseDroppedPath({
      type: "drop",
      paths: ["/projects/a", "/projects/b"],
      position: { x: 1, y: 2 },
    }),
    "/projects/a",
  );
});

test("hover and leave events never select a path", () => {
  assert.equal(
    chooseDroppedPath({ type: "over", position: { x: 1, y: 2 } }),
    null,
  );
  assert.equal(chooseDroppedPath({ type: "leave" }), null);
});

test("an empty drop is ignored", () => {
  assert.equal(
    chooseDroppedPath({ type: "drop", paths: [], position: { x: 1, y: 2 } }),
    null,
  );
});
