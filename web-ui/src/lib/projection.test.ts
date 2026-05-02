import { describe, expect, it } from "vitest";

import { lonLatToSvg } from "./projection";

describe("lonLatToSvg", () => {
  it("maps the equator/prime meridian to the SVG centre", () => {
    expect(lonLatToSvg(0, 0)).toEqual([512, 256]);
  });

  it("maps the (-180, 90) corner to (0, 0)", () => {
    expect(lonLatToSvg(-180, 90)).toEqual([0, 0]);
  });

  it("maps the (180, -90) corner to (1024, 512)", () => {
    expect(lonLatToSvg(180, -90)).toEqual([1024, 512]);
  });

  it("places Paris approximately where it should be", () => {
    const [x, y] = lonLatToSvg(2.35, 48.85);
    expect(x).toBeCloseTo(518.7, 1);
    expect(y).toBeCloseTo(117.06, 1);
  });

  it("places Sydney approximately where it should be", () => {
    const [x, y] = lonLatToSvg(151.21, -33.87);
    expect(x).toBeCloseTo(942.1, 1);
    expect(y).toBeCloseTo(352.36, 1);
  });
});
