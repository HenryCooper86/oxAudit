import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

/**
 * Component tests run in jsdom, which is not a browser and not Tauri.
 *
 * Anything a component reaches for that jsdom does not implement is stubbed
 * here rather than in each test, so a test that forgets to stub something fails
 * loudly on the missing API instead of passing against a half-real environment.
 */

afterEach(() => {
  cleanup();
});

// jsdom implements neither, and the workbench shell uses both for the
// collapsible panels and the theme.
if (!window.matchMedia) {
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
}

if (!globalThis.ResizeObserver) {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
}

if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = vi.fn();
}

// jsdom performs no layout, so `getClientRects()` returns an empty list for
// every element — including visible ones. Focus-trap code that filters
// candidates by "is it laid out?" therefore sees nothing focusable and behaves
// as though the dialog were empty.
//
// Reporting one box for elements that are not explicitly hidden is the closest
// honest approximation: it lets that logic run, while `display: none` and
// `hidden` still drop out the way they would in a browser.
const NO_LAYOUT = new DOMRect(0, 0, 0, 0);
const ONE_BOX = new DOMRect(0, 0, 100, 20);
Element.prototype.getClientRects = function getClientRects(this: Element) {
  const style = window.getComputedStyle(this);
  const hidden =
    style.display === "none" ||
    style.visibility === "hidden" ||
    (this as HTMLElement).hidden === true;
  const rects = hidden ? [] : [ONE_BOX];
  return Object.assign(rects, {
    item: (index: number) => rects[index] ?? null,
  }) as unknown as DOMRectList;
};
Element.prototype.getBoundingClientRect = function getBoundingClientRect(this: Element) {
  return this.getClientRects().length > 0 ? ONE_BOX : NO_LAYOUT;
};
