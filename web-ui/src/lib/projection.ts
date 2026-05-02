/**
 * Map projection helpers used by the world-map widget.
 *
 * The base SVG (``public/world-map.svg``) is rendered in the
 * 1024×512 plate-carrée (EPSG:4326) coordinate system; converting
 * a (longitude, latitude) pair into SVG pixel space is a one-line
 * affine transform.
 */

export const SVG_WIDTH = 1024;
export const SVG_HEIGHT = 512;

/** EPSG:4326 → SVG pixel projection. */
export function lonLatToSvg(lon: number, lat: number): [number, number] {
  const x = ((lon + 180) / 360) * SVG_WIDTH;
  const y = ((90 - lat) / 180) * SVG_HEIGHT;
  return [x, y];
}
