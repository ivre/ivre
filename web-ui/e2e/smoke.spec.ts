import { expect, test } from "@playwright/test";

/**
 * Smoke test: the app shell renders and the View section is the
 * default route. We do not exercise backend-dependent UI here
 * because ``pnpm dev`` runs without a real ``ivre httpd`` in CI.
 */
test("app shell loads and lands on View", async ({ page }) => {
  // The /cgi/config script tag will 404 in CI dev mode (no backend
  // running). We don't care for this smoke test.
  await page.route("**/cgi/config", (route) => route.fulfill({ status: 204 }));
  await page.route("**/cgi/**", (route) => route.fulfill({ status: 204 }));

  await page.goto("/");

  // Brand link visible.
  await expect(page.getByRole("link", { name: /IVRE/i })).toBeVisible();

  // Default redirect to /view → the View tab is current.
  await expect(page).toHaveURL(/#\/view/);
  await expect(page.getByRole("link", { name: "View" })).toHaveAttribute(
    "aria-current",
    "page",
  );

  // Filter input is present.
  await expect(page.getByRole("textbox", { name: /filter query/i })).toBeVisible();

  // Theme toggle is present.
  await expect(
    page.getByRole("button", { name: /switch to (dark|light) mode/i }),
  ).toBeVisible();
});

test("section nav switches to a stub", async ({ page }) => {
  await page.route("**/cgi/**", (route) => route.fulfill({ status: 204 }));
  await page.goto("/");
  await page.getByRole("link", { name: "RIR" }).click();
  await expect(page).toHaveURL(/#\/rir/);
  await expect(page.getByRole("heading", { name: /RIR/i })).toBeVisible();
  await expect(page.getByText(/under construction/i)).toBeVisible();
});

test("Active section renders the host-list page (no world map)", async ({
  page,
}) => {
  // No backend in CI dev mode; stub everything to 204.
  await page.route("**/cgi/**", (route) => route.fulfill({ status: 204 }));
  await page.goto("/");
  await page.getByRole("link", { name: "Active" }).click();
  await expect(page).toHaveURL(/#\/active/);
  await expect(page.getByRole("link", { name: "Active" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  // Same filter-bar UI as View (proves the page rendered, not the
  // "under construction" stub).
  await expect(
    page.getByRole("textbox", { name: /filter query/i }),
  ).toBeVisible();
  // The world map widget has its own ``role="img"`` with the SR-only
  // "World map showing the geographic distribution of results."
  // label; raw scans aren't typically GeoIP-enriched so the Active
  // section omits it entirely.
  await expect(page.getByLabel(/world map/i)).toHaveCount(0);
});

test("direct navigation to /view/host/<addr> opens the detail sheet", async ({
  page,
}) => {
  // Mock the single-host fetch so the route renders something.
  // ``page.route`` handlers stack LIFO and ``route.continue()`` forwards
  // the request to the actual network (no backend in CI dev), so we
  // dispatch from a single handler rather than chaining via
  // ``route.fallback()``.
  const sample = {
    addr: "1.2.3.4",
    infos: { country_code: "FR", country_name: "France" },
    ports: [
      { protocol: "tcp", port: 443, state_state: "open", service_name: "https" },
    ],
  };
  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/view") {
      const q = url.searchParams.get("q") ?? "";
      if (q.includes("host:")) {
        return route.fulfill({
          status: 200,
          contentType: "application/x-ndjson",
          body: JSON.stringify(sample) + "\n",
        });
      }
      return route.fulfill({ status: 200, body: "" });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/#/view/host/1.2.3.4");
  await expect(
    page.getByRole("heading", { name: "1.2.3.4" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /copy permalink/i }),
  ).toBeVisible();
});

test("UserMenu is hidden when auth is disabled", async ({ page }) => {
  // Default: ``window.config`` is unset (no backend) → auth_enabled
  // defaults to false → the menu renders nothing.
  //
  // Track every ``/cgi/auth/*`` request so we can assert below
  // that none was issued. The auth-related react-query hooks
  // (``useAuthMe`` / ``useAuthConfig``) gate on
  // ``isAuthEnabled()``; if either ever fires when auth is
  // disabled, the operator's httpd access log gains a 404 per
  // page load (``/cgi/auth/me`` and ``/cgi/auth/config`` are
  // not registered server-side in that mode).
  const authRequests: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/cgi/auth/")) {
      authRequests.push(url.pathname);
    }
  });
  await page.route("**/cgi/**", (route) => route.fulfill({ status: 204 }));
  await page.goto("/");
  await expect(page.getByRole("button", { name: /sign in/i })).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: /account menu/i }),
  ).toHaveCount(0);
  // Give react-query a tick in case it would have fired an
  // eager request (it should not — the queries are gated).
  await page.waitForLoadState("networkidle");
  expect(authRequests).toEqual([]);
});

test("UserMenu shows Sign in when auth is enabled and the user is anonymous", async ({
  page,
}) => {
  // Mock the legacy ``/cgi/config`` script tag to mutate the
  // ``var config = {}`` declared inline in ``index.html`` —
  // matches what the production backend does, and avoids the
  // ``addInitScript`` ordering race that surfaced on Node 22
  // when the bundle parse time pushed the init-script past the
  // ``<script src="/cgi/config">`` tag.
  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/config") {
      return route.fulfill({
        status: 200,
        contentType: "application/javascript",
        body: "config.auth_enabled = true;\n",
      });
    }
    if (url.pathname === "/cgi/auth/me") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ authenticated: false }),
      });
    }
    if (url.pathname === "/cgi/auth/config") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          enabled: true,
          providers: ["google", "oidc"],
          magic_link: true,
          provider_labels: { oidc: "Corp SSO" },
        }),
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/");
  const signInButton = page.getByRole("button", { name: /sign in/i });
  await expect(signInButton).toBeVisible();
  await signInButton.click();

  // Dialog with provider buttons.
  await expect(
    page.getByRole("dialog", { name: /sign in to ivre/i }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /continue with google/i }),
  ).toBeVisible();
  // Operator-defined OIDC label is honoured.
  await expect(
    page.getByRole("button", { name: /continue with corp sso/i }),
  ).toBeVisible();
  // Magic-link form present when enabled server-side.
  await expect(
    page.getByRole("textbox", { name: /email me a sign-in link/i }),
  ).toBeVisible();
});

test("UserMenu shows the user identity when authenticated", async ({
  page,
}) => {
  // Same race-free ``/cgi/config`` mock as the anonymous test.
  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/config") {
      return route.fulfill({
        status: 200,
        contentType: "application/javascript",
        body: "config.auth_enabled = true;\n",
      });
    }
    if (url.pathname === "/cgi/auth/me") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          authenticated: true,
          email: "alice@example.com",
          display_name: "Alice",
          is_admin: true,
          groups: ["staff"],
        }),
      });
    }
    if (url.pathname === "/cgi/auth/config") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          enabled: true,
          providers: ["google"],
          magic_link: false,
        }),
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/");
  const accountButton = page.getByRole("button", { name: /account menu/i });
  await expect(accountButton).toBeVisible();
  await expect(accountButton).toContainText("Alice");
  await accountButton.click();
  // Dropdown shows the email, an Admin shortcut (because is_admin),
  // and a Sign out item.
  await expect(page.getByText("alice@example.com")).toBeVisible();
  await expect(
    page.getByRole("menuitem", { name: /admin/i }),
  ).toBeVisible();
  await expect(
    page.getByRole("menuitem", { name: /sign out/i }),
  ).toBeVisible();
});

test("Passive section renders the timeline + record list", async ({ page }) => {
  // Two passive records: a 60-second-span DNS A answer with
  // count=120 (density 2/s), and an instant HTTP server header
  // with count=1 (density 1/s). The timeline should render two
  // SVG elements (one ``<line>`` for the span, one ``<circle>``
  // for the instant), and the cards should appear below.
  const records = [
    {
      schema_version: 3,
      recontype: "DNS_ANSWER",
      rrtype: "A",
      source: "A",
      sensor: "TEST",
      value: "example.com",
      addr: "1.2.3.4",
      count: 120,
      firstseen: 1_700_000_000,
      lastseen: 1_700_000_060,
    },
    {
      schema_version: 3,
      recontype: "HTTP_SERVER_HEADER",
      source: "SERVER",
      sensor: "TEST",
      value: "Apache",
      addr: "1.2.3.4",
      port: 80,
      count: 1,
      firstseen: 1_700_000_500,
      lastseen: 1_700_000_500,
    },
  ];
  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/passive") {
      return route.fulfill({
        status: 200,
        contentType: "application/x-ndjson",
        body: records.map((r) => JSON.stringify(r)).join("\n") + "\n",
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/#/passive");

  // The two records render as two cards. ``exact: true`` so we
  // match only the card body, not the SVG ``<title>`` tooltip
  // text on the corresponding timeline element.
  await expect(
    page.getByText("example.com → 1.2.3.4", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Apache", { exact: true })).toBeVisible();

  // No "under construction" stub.
  await expect(page.getByText(/under construction/i)).toHaveCount(0);

  // The timeline widget is present (SR-only label) and contains
  // the right number of plotted records.
  await expect(
    page.getByLabel(/timeline of 2 passive observations/i),
  ).toBeVisible();

  // Clicking a card's source chip adds the
  // ``source:RECONTYPE:SOURCE`` tuple filter (passive's
  // ``source`` is meaningful only relative to ``recontype``).
  // The renderer quotes values containing a ``:`` literal, and
  // the URL is then percent-encoded; check the decoded form
  // rather than coupling to the wire shape.
  await page
    .getByRole("button", { name: /source:SERVER/i })
    .first()
    .click();
  await expect(page).toHaveURL((url) =>
    decodeURIComponent(url.toString()).includes(
      'source:"HTTP_SERVER_HEADER:SERVER"',
    ),
  );
});

test("Admin section renders for admin users (users panel + API keys)", async ({
  page,
}) => {
  // ``/cgi/config`` mocked to set ``window.config.auth_enabled = true``
  // (matches the production ``var config = {}`` then
  // ``config.auth_enabled = ...`` script body) so the new
  // UserMenu / Admin gate sees auth as enabled. Then mock the
  // admin endpoints with two-user / one-key fixtures.
  const users = [
    {
      email: "alice@example.com",
      display_name: "Alice",
      is_admin: true,
      is_active: true,
      groups: ["staff"],
      created_at: "2024-01-02T10:00:00",
      last_login: "2024-03-15T09:30:00",
    },
    {
      email: "bob@example.com",
      is_admin: false,
      is_active: true,
      groups: [],
      created_at: "2024-02-01T08:00:00",
      last_login: null,
    },
  ];
  const keys = [
    {
      key_hash: "h0",
      key_prefix: "ivre_aaaa",
      user_email: "alice@example.com",
      name: "ci-pipeline",
      created_at: "2024-01-02T10:00:00",
      last_used: null,
      expires_at: null,
    },
  ];
  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/config") {
      return route.fulfill({
        status: 200,
        contentType: "application/javascript",
        body: "config.auth_enabled = true;\n",
      });
    }
    if (url.pathname === "/cgi/auth/me") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          authenticated: true,
          email: "alice@example.com",
          display_name: "Alice",
          is_admin: true,
          groups: ["staff"],
        }),
      });
    }
    if (url.pathname === "/cgi/auth/config") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          enabled: true,
          providers: ["google"],
          magic_link: false,
        }),
      });
    }
    if (url.pathname === "/cgi/auth/admin/users") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(users),
      });
    }
    if (url.pathname === "/cgi/auth/api-keys") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(keys),
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/#/admin");

  // Page heading + admin user identity rendered.
  await expect(
    page.getByRole("heading", { name: /^Admin$/, level: 1 }),
  ).toBeVisible();
  await expect(page.getByText("alice@example.com").first()).toBeVisible();

  // Users panel is the default tab — both users render.
  await expect(page.getByText("Alice").first()).toBeVisible();
  await expect(page.getByText("bob@example.com").first()).toBeVisible();

  // Switch to API keys tab — the listed key is visible.
  await page.getByRole("tab", { name: /api keys/i }).click();
  await expect(page.getByText("ci-pipeline")).toBeVisible();
  await expect(page.getByText(/ivre_aaaa…/)).toBeVisible();
});

test("Admin section gates non-admin users with a placeholder", async ({
  page,
}) => {
  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/config") {
      return route.fulfill({
        status: 200,
        contentType: "application/javascript",
        body: "config.auth_enabled = true;\n",
      });
    }
    if (url.pathname === "/cgi/auth/me") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          authenticated: true,
          email: "bob@example.com",
          is_admin: false,
        }),
      });
    }
    if (url.pathname === "/cgi/auth/config") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          enabled: true,
          providers: [],
          magic_link: false,
        }),
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/#/admin");
  await expect(
    page.getByText(/does not have admin privileges/i),
  ).toBeVisible();
  // The admin endpoints must not have been hit.
  // (No assertion on requests because ``page.route`` would 204
  // them anyway — but the placeholder confirms the gate is
  // working.)
});
