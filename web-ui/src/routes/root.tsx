import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";
import { createHashRouter, Navigate, RouterProvider } from "react-router-dom";

import { AppShell } from "@/components/AppShell";
import { SectionStub } from "@/components/SectionStub";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { isModuleEnabled } from "@/lib/config";
import { DEFAULT_SECTION, type SectionId } from "@/lib/sections";

import { ActiveRoute } from "./active";
import { AdminRoute } from "./admin";
import { ApiKeysRoute } from "./api-keys";
import { DnsRoute } from "./dns";
import { FlowRoute } from "./flow";
import { PassiveRoute } from "./passive-list";
import { RirRoute } from "./rir";
import { ViewRoute } from "./view";

/** Wrap a section's route element so visiting it via a direct
 *  URL (bookmarks, refreshes) renders the "not exposed" stub
 *  when the server's ``WEB_MODULES`` allowlist disables that
 *  module. The nav is filtered separately in ``AppShell``; this
 *  is the matching gate for direct-URL access. ``module`` is
 *  passed to the stub so its label resolves via ``getSection``
 *  (the explicit route has no ``:sectionId`` URL param). */
function gateModule(
  module: SectionId,
  element: React.ReactElement,
): React.ReactElement {
  return isModuleEnabled(module) ? element : <SectionStub forceId={module} />;
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Filter changes are explicit (URL-driven), so we don't need
      // refetch-on-window-focus for the data-search case.
      refetchOnWindowFocus: false,
      staleTime: 30_000,
      retry: false,
    },
  },
});

const router = createHashRouter([
  {
    path: "/",
    element: <AppShell />,
    children: [
      { index: true, element: <Navigate to={`/${DEFAULT_SECTION}`} replace /> },
      // Section routes are wrapped in ``gateModule`` so direct
      // navigation to a server-disabled module renders the "not
      // exposed" stub rather than the section UI. The nav is
      // filtered server-aware in ``AppShell``; this is the
      // matching gate for bookmarked / shared URLs.
      { path: "view", element: gateModule("view", <ViewRoute />) },
      // Per-host deep link. The same component renders both
      // ``/<sectionId>`` (no detail open) and
      // ``/<sectionId>/host/<addr>`` (sheet pre-opened with that
      // host). View and Active share the same ``HostListRoute``;
      // only the section config differs.
      { path: "view/host/:addr", element: gateModule("view", <ViewRoute />) },
      { path: "active", element: gateModule("active", <ActiveRoute />) },
      {
        path: "active/host/:addr",
        element: gateModule("active", <ActiveRoute />),
      },
      { path: "passive", element: gateModule("passive", <PassiveRoute />) },
      // DNS has its own ``/cgi/dns`` endpoint that merges
      // active scans + passive observations server-side; see
      // ``ivre/web/app.py``'s ``get_dns``.
      { path: "dns", element: gateModule("dns", <DnsRoute />) },
      // RIR records (RPSL inet[6]num + aut-num) from the
      // regional dumps. Default sort is narrowest-range first
      // so a ``host:`` / ``net:`` filter surfaces the leaf
      // allocation at the top.
      { path: "rir", element: gateModule("rir", <RirRoute />) },
      // Flow graph (Zeek / netflow / iptables ingestion). The
      // ``/cgi/flows`` route returns a graph object; the
      // FlowRoute renders it via cytoscape.
      { path: "flow", element: gateModule("flow", <FlowRoute />) },
      // Account / admin pages — reachable from the user menu
      // only; intentionally absent from the section nav. Not
      // gated by ``WEB_MODULES`` (they have their own
      // ``WEB_AUTH_ENABLED`` / ``is_admin`` knobs).
      { path: "admin", element: <AdminRoute /> },
      { path: "api-keys", element: <ApiKeysRoute /> },
      { path: ":sectionId", element: <SectionStub /> },
      { path: ":sectionId/*", element: <SectionStub /> },
    ],
  },
]);

export function Root() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider
        attribute="class"
        defaultTheme="system"
        enableSystem
        disableTransitionOnChange
      >
        <TooltipProvider delayDuration={300}>
          <RouterProvider router={router} />
          <Toaster />
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}
