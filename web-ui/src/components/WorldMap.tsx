import { useEffect, useId, useState } from "react";

import { useCoordinates } from "@/lib/api";
import { lonLatToSvg, SVG_HEIGHT, SVG_WIDTH } from "@/lib/projection";

export interface WorldMapProps {
  mapEndpoint: string | undefined;
  query: string;
}

/**
 * World map widget — a static SVG (the prototype's
 * ``world-map.svg``, public domain) overlaid with one circle per
 * GeoJSON Point in ``/cgi/<purpose>/coordinates``.
 *
 * Air-gapped: no tile server, no third-party fetch. The base SVG
 * is shipped under ``public/world-map.svg``.
 */
export function WorldMap({ mapEndpoint, query }: WorldMapProps) {
  const titleId = useId();
  const [svgMarkup, setSvgMarkup] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch("world-map.svg", { credentials: "same-origin" })
      .then((r) => r.text())
      .then((text) => {
        if (!cancelled) setSvgMarkup(text);
      })
      .catch(() => {
        if (!cancelled) setSvgMarkup(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const { data } = useCoordinates(mapEndpoint, { q: query });

  const points = data?.geometries ?? [];
  const max = points.reduce(
    (m, g) => Math.max(m, g.properties?.count ?? 1),
    1,
  );

  return (
    <div
      className="relative aspect-[2/1] w-full overflow-hidden rounded-md border border-border bg-muted/30"
      role="img"
      aria-labelledby={titleId}
    >
      <span id={titleId} className="sr-only">
        World map showing the geographic distribution of results.
      </span>
      {svgMarkup ? (
        // The base SVG has hard-coded ``width="1024" height="512"``
        // attributes; force-fill the container with ``[&_svg]:!h-full
        // [&_svg]:!w-full`` so it scales with the parent's
        // aspect-[2/1] box. ``preserveAspectRatio`` is already on the
        // root SVG so the projection stays correct.
        //
        // Theming: the SVG (patched by the prototype before being
        // checked in) carries ``class="map-ocean"`` on the ocean
        // ``<rect>`` and ``class="map-countries"`` on the parent
        // ``<g>`` of the country paths. The element's own inline
        // ``style="fill:..."`` keeps the warm light-mode tones
        // (``#c5e1f5`` ocean, ``#d9d9d9`` countries) by default. In
        // dark mode we recolour to a blue-on-blue palette via
        // ``!fill`` / ``!stroke`` to override the inline styles.
        <div
          className="absolute inset-0 [&_svg]:!h-full [&_svg]:!w-full dark:[&_.map-ocean]:!fill-blue-500 dark:[&_.map-countries]:!fill-blue-900 dark:[&_.map-countries]:!stroke-blue-800"
          dangerouslySetInnerHTML={{ __html: svgMarkup }}
        />
      ) : null}
      <svg
        viewBox={`0 0 ${SVG_WIDTH} ${SVG_HEIGHT}`}
        preserveAspectRatio="xMidYMid meet"
        className="absolute inset-0 h-full w-full"
        aria-hidden
      >
        {points.map((g, i) => {
          const [lon, lat] = g.coordinates;
          const [x, y] = lonLatToSvg(lon, lat);
          const count = g.properties?.count ?? 1;
          const radius = 2 + Math.round((count / max) * 8);
          return (
            <circle
              key={i}
              cx={x}
              cy={y}
              r={radius}
              className="fill-orange-500/80 stroke-orange-700 dark:fill-orange-400/80 dark:stroke-orange-200"
              strokeWidth={0.5}
            >
              <title>{count} result{count > 1 ? "s" : ""}</title>
            </circle>
          );
        })}
      </svg>
    </div>
  );
}
