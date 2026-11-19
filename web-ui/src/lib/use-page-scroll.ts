import { useLayoutEffect, useRef, type RefObject } from "react";
import { useLocation, useNavigationType } from "react-router-dom";

const positions = new Map<string, number>();

export function savedScrollPosition(
  key: string | undefined,
): number | undefined {
  return key ? positions.get(key) : undefined;
}

/** Coordinate history restoration and report section jumps after data renders.
 * Back/Forward restores a saved reading position; explicit section links and
 * fresh permalinks jump to their target. Data updates alone never re-anchor. */
export function usePageScroll(
  ready = true,
  fallback = 0,
  {
    section,
    root,
  }: {
    section?: string | null;
    root?: RefObject<HTMLElement | null>;
  } = {},
): void {
  const { key } = useLocation();
  const navigationType = useNavigationType();
  const position = useRef(0);
  useLayoutEffect(() => {
    if (!ready) return;
    const saved = positions.get(key);
    let applied = false;
    const frame = requestAnimationFrame(() => {
      const target = section ? document.getElementById(section) : null;
      if (navigationType === "POP" && saved !== undefined) {
        window.scrollTo(0, saved);
      } else if (target && root?.current?.contains(target)) {
        target.scrollIntoView({ block: "start" });
        target.focus({ preventScroll: true });
      } else {
        window.scrollTo(0, saved ?? fallback);
      }
      position.current = window.scrollY;
      applied = true;
    });
    const track = () => {
      if (applied) position.current = window.scrollY;
    };
    window.addEventListener("scroll", track, { passive: true });
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("scroll", track);
      // StrictMode can clean up before the first frame. An unperformed scroll
      // must not create a saved zero that masks a fresh section permalink.
      if (!applied) return;
      positions.set(key, position.current);
      const oldest = positions.keys().next().value;
      if (positions.size > 100 && oldest !== undefined)
        positions.delete(oldest);
    };
  }, [key, ready, fallback, navigationType, section, root]);
}
