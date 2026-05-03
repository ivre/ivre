import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";
import { createHashRouter, Navigate, RouterProvider } from "react-router-dom";

import { AppShell } from "@/components/AppShell";
import { SectionStub } from "@/components/SectionStub";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { DEFAULT_SECTION } from "@/lib/sections";

import { ActiveRoute } from "./active";
import { AdminRoute } from "./admin";
import { DnsRoute } from "./dns";
import { PassiveRoute } from "./passive-list";
import { ViewRoute } from "./view";

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
      { path: "view", element: <ViewRoute /> },
      // Per-host deep link. The same component renders both
      // ``/<sectionId>`` (no detail open) and
      // ``/<sectionId>/host/<addr>`` (sheet pre-opened with that
      // host). View and Active share the same ``HostListRoute``;
      // only the section config differs.
      { path: "view/host/:addr", element: <ViewRoute /> },
      { path: "active", element: <ActiveRoute /> },
      { path: "active/host/:addr", element: <ActiveRoute /> },
      { path: "passive", element: <PassiveRoute /> },
      // DNS has its own ``/cgi/dns`` endpoint that merges
      // active scans + passive observations server-side; see
      // ``ivre/web/app.py``'s ``get_dns``.
      { path: "dns", element: <DnsRoute /> },
      { path: "admin", element: <AdminRoute /> },
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
