import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { StrictMode, useRef } from "react";
import {
  Link,
  MemoryRouter,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { usePageScroll } from "./use-page-scroll";

let scrollY: number;
let nextFrame: number;
const frames = new Map<number, FrameRequestCallback>();
const originalScrollIntoView = HTMLElement.prototype.scrollIntoView;

function flushFrames() {
  act(() => {
    const pending = [...frames.values()];
    frames.clear();
    for (const callback of pending) callback(0);
  });
}

function scrollToReadingPosition(value: number) {
  scrollY = value;
  fireEvent.scroll(window);
}

function ScrollPage({ ready, revision }: { ready: boolean; revision: number }) {
  const root = useRef<HTMLDivElement>(null);
  const { search } = useLocation();
  usePageScroll(ready, 75, {
    section: new URLSearchParams(search).get("section"),
    root,
  });
  return (
    <>
      <section id="outside-report" tabIndex={-1}>
        Outside the report
      </section>
      {ready ? (
        <div ref={root} data-revision={revision}>
          <section id="port-tcp-443" tabIndex={-1}>
            Certificate output
          </section>
        </div>
      ) : (
        <p>Loading</p>
      )}
      <Link to="/other">Leave report</Link>
      <Link to="/report?section=port-tcp-443">Jump to certificate</Link>
    </>
  );
}

function HistoryControls() {
  const navigate = useNavigate();
  return (
    <>
      <button
        onClick={() => {
          void navigate(-1);
        }}
      >
        Back
      </button>
      <button
        onClick={() => {
          void navigate(1);
        }}
      >
        Forward
      </button>
    </>
  );
}

function renderPage(section = "port-tcp-443", ready = true) {
  const entry = {
    pathname: "/report",
    search: section ? `?section=${section}` : "",
    key: crypto.randomUUID(),
  };
  const tree = (isReady: boolean, revision = 0) => (
    <StrictMode>
      <MemoryRouter initialEntries={[entry]}>
        <HistoryControls />
        <Routes>
          <Route
            path="/report"
            element={<ScrollPage ready={isReady} revision={revision} />}
          />
          <Route path="/other" element={<p>Other page</p>} />
        </Routes>
      </MemoryRouter>
    </StrictMode>
  );
  const result = render(tree(ready));
  return {
    ...result,
    update: (isReady: boolean, revision = 0) =>
      result.rerender(tree(isReady, revision)),
  };
}

beforeEach(() => {
  scrollY = 0;
  nextFrame = 0;
  frames.clear();
  vi.spyOn(window, "scrollY", "get").mockImplementation(() => scrollY);
  vi.spyOn(window, "scrollTo").mockImplementation((_x, y) => {
    scrollY = y ?? 0;
  });
  HTMLElement.prototype.scrollIntoView = vi.fn(() => {
    scrollY = 400;
  });
  vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => {
    frames.set(++nextFrame, callback);
    return nextFrame;
  });
  vi.stubGlobal("cancelAnimationFrame", (frame: number) => {
    frames.delete(frame);
  });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  HTMLElement.prototype.scrollIntoView = originalScrollIntoView;
});

describe("page scroll coordination", () => {
  it("honors a fresh section permalink on initial POP, including StrictMode", () => {
    renderPage();
    expect(HTMLElement.prototype.scrollIntoView).not.toHaveBeenCalled();
    flushFrames();
    expect(
      HTMLElement.prototype.scrollIntoView,
    ).toHaveBeenCalledExactlyOnceWith({ block: "start" });
    expect(window.scrollTo).not.toHaveBeenCalled();
    expect(screen.getByText("Certificate output")).toHaveFocus();
  });

  it.each([0, 850])(
    "restores saved position %i instead of the URL section on Back/Forward",
    (position) => {
      renderPage();
      flushFrames();
      scrollToReadingPosition(position);
      fireEvent.click(screen.getByRole("link", { name: "Leave report" }));
      scrollY = 0;
      fireEvent.click(screen.getByRole("button", { name: "Back" }));
      flushFrames();
      expect(window.scrollTo).toHaveBeenLastCalledWith(0, position);
      expect(HTMLElement.prototype.scrollIntoView).toHaveBeenCalledTimes(1);
      expect(screen.getByText("Certificate output")).not.toHaveFocus();
      fireEvent.click(screen.getByRole("button", { name: "Forward" }));
      fireEvent.click(screen.getByRole("button", { name: "Back" }));
      flushFrames();
      expect(window.scrollTo).toHaveBeenLastCalledWith(0, position);
      expect(HTMLElement.prototype.scrollIntoView).toHaveBeenCalledTimes(1);
    },
  );

  it("honors an explicit click on the same section after manually scrolling away", () => {
    renderPage();
    flushFrames();
    scrollToReadingPosition(850);
    fireEvent.click(screen.getByRole("link", { name: "Jump to certificate" }));
    flushFrames();
    expect(HTMLElement.prototype.scrollIntoView).toHaveBeenCalledTimes(2);
    expect(scrollY).toBe(400);
  });

  it("waits for the report to render and does not re-anchor on data updates", () => {
    const page = renderPage("port-tcp-443", false);
    flushFrames();
    expect(window.scrollTo).not.toHaveBeenCalled();
    expect(HTMLElement.prototype.scrollIntoView).not.toHaveBeenCalled();
    page.update(true);
    flushFrames();
    expect(HTMLElement.prototype.scrollIntoView).toHaveBeenCalledTimes(1);
    scrollToReadingPosition(850);
    page.update(true, 1);
    flushFrames();
    expect(scrollY).toBe(850);
    expect(HTMLElement.prototype.scrollIntoView).toHaveBeenCalledTimes(1);
    expect(window.scrollTo).not.toHaveBeenCalled();
  });

  it.each(["missing", "outside-report", ""])(
    "uses the fallback for section %j without focusing outside the report",
    (section) => {
      renderPage(section);
      flushFrames();
      expect(window.scrollTo).toHaveBeenCalledExactlyOnceWith(0, 75);
      expect(HTMLElement.prototype.scrollIntoView).not.toHaveBeenCalled();
      expect(screen.getByText("Outside the report")).not.toHaveFocus();
    },
  );

  it("does not save a placeholder zero when navigation cancels the first frame", () => {
    renderPage();
    fireEvent.click(screen.getByRole("link", { name: "Leave report" }));
    flushFrames();
    expect(window.scrollTo).not.toHaveBeenCalled();
    expect(HTMLElement.prototype.scrollIntoView).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    flushFrames();
    expect(HTMLElement.prototype.scrollIntoView).toHaveBeenCalledTimes(1);
    expect(scrollY).toBe(400);
  });
});
