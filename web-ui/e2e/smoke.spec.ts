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

test("section nav reaches the catch-all stub for unknown ids", async ({
  page,
}) => {
  // Every known section now has a real route; the stub is only
  // reachable via direct navigation to an unknown section id
  // (or via ``WEB_MODULES`` disabling a known one \u2014 covered
  // by a separate spec).
  await page.route("**/cgi/**", (route) => route.fulfill({ status: 204 }));
  await page.goto("/#/madeupsection");
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
  // Active replaces the absent map with the scan-timeline widget
  // in the same left-rail slot. Empty backend -> empty-state
  // string from the Timeline component.
  await expect(page.getByText(/no scans to plot/i)).toBeVisible();
});

test("Active section renders the scan timeline next to the host list", async ({
  page,
}) => {
  // Two scans: a 60-second active scan and an instant blip
  // (starttime == endtime). The Timeline should render a line
  // for the first and a circle for the second; the SR-only
  // accessibility label reports the total count.
  const hosts = [
    {
      addr: "10.0.0.1",
      starttime: "2024-01-02 10:00:00",
      endtime: "2024-01-02 10:01:00",
      // Active scan documents carry ``source`` as a plain
      // string (only view records merge into an array). The
      // card must render either form without blowing up; this
      // also pins the regression where ``sources.map(...)``
      // assumed an array unconditionally.
      source: "scan-2024-Q1",
      infos: { country_code: "FR", country_name: "France" },
      ports: [
        {
          protocol: "tcp",
          port: 22,
          state_state: "open",
          service_name: "ssh",
        },
      ],
    },
    {
      addr: "10.0.0.2",
      starttime: "2024-01-02 10:05:00",
      endtime: "2024-01-02 10:05:00",
      // Other shape: array. Both must round-trip through the
      // card layer.
      source: ["scan-2024-Q2"],
      ports: [],
    },
  ];
  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/scans") {
      return route.fulfill({
        status: 200,
        contentType: "application/x-ndjson",
        body: hosts.map((h) => JSON.stringify(h)).join("\n") + "\n",
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/#/active");

  // Both hosts render as cards. Match the headings specifically
  // so we don't accidentally pick up the SVG ``<title>`` tooltip
  // text on the corresponding timeline element.
  await expect(
    page.getByRole("heading", { name: "10.0.0.1" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "10.0.0.2" }),
  ).toBeVisible();

  // The timeline widget is present in the left rail with the
  // expected accessible label. ``itemLabel`` on the Timeline
  // component pluralises "scan" -> "scans" for >1 records.
  await expect(page.getByLabel(/timeline of 2 scans/i)).toBeVisible();

  // Both forms of the ``source`` field render: the card
  // surfaces them as click-to-filter chips, regardless of
  // whether the wire shape was a string or an array.
  await expect(page.getByRole("button", { name: /scan-2024-Q1/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /scan-2024-Q2/ })).toBeVisible();
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
  // Dropdown shows the email, the API-keys shortcut (any authed
  // user), an Admin shortcut (because is_admin), and a Sign out
  // item.
  await expect(page.getByText("alice@example.com")).toBeVisible();
  await expect(
    page.getByRole("menuitem", { name: /api keys/i }),
  ).toBeVisible();
  await expect(
    page.getByRole("menuitem", { name: /admin/i }),
  ).toBeVisible();
  await expect(
    page.getByRole("menuitem", { name: /sign out/i }),
  ).toBeVisible();

  // Account / admin pages must NOT appear in the section nav.
  // The nav lives in a top-level <nav>; assert no link with the
  // hash route ``#/admin`` or ``#/api-keys`` lives inside it.
  const sectionNav = page.locator("header nav").first();
  await expect(sectionNav.locator('a[href="#/admin"]')).toHaveCount(0);
  await expect(sectionNav.locator('a[href="#/api-keys"]')).toHaveCount(0);
});

test("Non-admin user sees API keys in the menu but no Admin shortcut", async ({
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

  await page.goto("/");
  await page.getByRole("button", { name: /account menu/i }).click();

  // API keys is always available to authenticated users …
  await expect(
    page.getByRole("menuitem", { name: /api keys/i }),
  ).toBeVisible();
  // … but Admin requires ``is_admin`` and must be absent here.
  await expect(
    page.getByRole("menuitem", { name: /admin/i }),
  ).toHaveCount(0);
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
  // Two keys belonging to two different users — the admin
  // panel hits the cross-user audit endpoint and must surface
  // both rows with their owner email visible.
  const adminKeys = [
    {
      key_hash: "h0",
      key_prefix: "ivre_aaaa",
      user_email: "alice@example.com",
      name: "ci-pipeline",
      created_at: "2024-01-02T10:00:00",
      last_used: null,
      expires_at: null,
    },
    {
      key_hash: "h1",
      key_prefix: "ivre_bbbb",
      user_email: "bob@example.com",
      name: "dashboard",
      created_at: "2024-02-01T08:00:00",
      last_used: "2024-03-01T12:00:00",
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
    if (url.pathname === "/cgi/auth/admin/api-keys") {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(adminKeys),
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

  // Switch to API keys tab — admin sees keys belonging to
  // *every* user, with the owner email visible per row.
  await page.getByRole("tab", { name: /api keys/i }).click();
  await expect(page.getByText("ci-pipeline")).toBeVisible();
  await expect(page.getByText(/ivre_aaaa…/)).toBeVisible();
  await expect(page.getByText("dashboard")).toBeVisible();
  await expect(page.getByText(/ivre_bbbb…/)).toBeVisible();
  // Owner emails appear in the rows (Alice's appears at least
  // twice: once in the admin breadcrumb, once in the row).
  await expect(page.getByText("bob@example.com")).toBeVisible();
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

test("API-keys self-service page lists the user's own keys", async ({
  page,
}) => {
  // Self-service path: any authenticated user (admin or not)
  // sees their own keys via ``/cgi/auth/api-keys``. The page
  // is reached from the user menu, never from the section nav.
  const myKeys = [
    {
      key_hash: "self-h0",
      key_prefix: "ivre_self",
      user_email: "bob@example.com",
      name: "personal-cli",
      created_at: "2024-04-01T09:00:00",
      last_used: "2024-04-15T11:00:00",
      expires_at: null,
    },
  ];
  let createCalls = 0;
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
    if (url.pathname === "/cgi/auth/api-keys") {
      if (route.request().method() === "POST") {
        createCalls += 1;
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            key: "ivre_secrettoken_xyz",
            name: "new-cli",
          }),
        });
      }
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(myKeys),
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/#/api-keys");

  // Heading + identity. ``bob@example.com`` also appears in the
  // UserMenu trigger (top-right corner); scope to ``<main>`` so
  // we assert specifically on the page body breadcrumb.
  await expect(
    page.getByRole("heading", { name: /^API keys$/, level: 1 }),
  ).toBeVisible();
  await expect(
    page.getByRole("main").getByText("bob@example.com"),
  ).toBeVisible();

  // Existing key rendered.
  await expect(page.getByText("personal-cli")).toBeVisible();
  await expect(page.getByText(/ivre_self…/)).toBeVisible();

  // Create-key form: type a name, hit Create, the secret modal
  // appears with the one-shot value (rendered inside a readonly
  // ``<input>`` so we assert on the value attribute, not the
  // text content).
  await page
    .getByRole("textbox", { name: /new api key name/i })
    .fill("new-cli");
  await page.getByRole("button", { name: /^Create$/ }).click();
  await expect(
    page.getByRole("heading", { name: /api key created/i }),
  ).toBeVisible();
  await expect(
    page.getByRole("textbox", { name: /new api key value/i }),
  ).toHaveValue("ivre_secrettoken_xyz");
  expect(createCalls).toBe(1);
});

test("API-keys page gates anonymous users with a placeholder", async ({
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
        body: JSON.stringify({ authenticated: false }),
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

  await page.goto("/#/api-keys");
  await expect(
    page.getByText(/sign in to manage your api keys/i),
  ).toBeVisible();
});

test("DNS section renders merged pseudo-records from /cgi/dns", async ({
  page,
}) => {
  // The DNS section talks to a dedicated ``/cgi/dns`` endpoint
  // that merges active + passive observations into a single
  // ``(name, addr)`` pseudo-record stream. Mock that endpoint
  // with two rows and assert they render with their type /
  // source badges and merged ``×count``.
  const dnsRecords = [
    {
      name: "example.com",
      addr: "1.2.3.4",
      count: 122,
      firstseen: 1_700_000_000,
      lastseen: 1_700_000_500,
      types: ["A", "user"],
      sources: ["scan-2024-Q1", "sensor1"],
    },
    {
      name: "host.example.com",
      addr: "1.2.3.5",
      count: 1,
      firstseen: 1_700_000_500,
      lastseen: 1_700_000_500,
      types: ["PTR"],
      sources: ["sensor2"],
    },
  ];
  const dnsQueries: string[] = [];
  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/dns") {
      dnsQueries.push(url.searchParams.get("q") ?? "");
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(dnsRecords),
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/#/dns");

  // Heading + both rows render.
  await expect(
    page.getByRole("heading", { name: /DNS answers/i }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /^example\.com$/ }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /^host\.example\.com$/ }),
  ).toBeVisible();

  // Type and source badges from the merge are visible.
  await expect(page.getByText("A", { exact: true }).first()).toBeVisible();
  await expect(
    page.getByText("user", { exact: true }).first(),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /scan-2024-Q1/ }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /sensor1/ }),
  ).toBeVisible();

  // Merged count.
  await expect(page.getByText("×122")).toBeVisible();

  // The endpoint received the user's (empty) ``q``.
  expect(dnsQueries.length).toBeGreaterThan(0);
  expect(dnsQueries[0]).toBe("");
});

test("DNS section forwards user-typed filters to /cgi/dns", async ({
  page,
}) => {
  const dnsQueries: string[] = [];
  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/dns") {
      dnsQueries.push(url.searchParams.get("q") ?? "");
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: "[]",
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/#/dns?q=hostname%3Aexample.com");
  await page.waitForLoadState("networkidle");

  expect(dnsQueries.length).toBeGreaterThan(0);
  expect(dnsQueries[dnsQueries.length - 1]).toBe("hostname:example.com");
});

test("RIR section renders inet[6]num and aut-num records", async ({
  page,
}) => {
  // One inet[6]num record (a /24 — should collapse to its CIDR
  // form in the headline) and one aut-num record. The card
  // exposes a "Show more" toggle revealing the RPSL key/value
  // table for any extra fields the dump carried.
  const records = [
    {
      schema_version: 2,
      start: "192.0.2.0",
      stop: "192.0.2.255",
      size: 256,
      netname: "EXAMPLE-NET",
      descr: "Example Allocation",
      country: "FR",
      org: "Example Org",
      source_file: "ripe.db.inetnum.gz",
      "mnt-by": "EXAMPLE-MNT",
      status: "ASSIGNED PA",
    },
    {
      schema_version: 2,
      "aut-num": 64512,
      "as-name": "EXAMPLE-AS",
      descr: "Example Autonomous System",
      country: "FR",
      source_file: "ripe.db.aut-num.gz",
    },
  ];
  const queries: string[] = [];
  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/rir") {
      queries.push(url.searchParams.get("q") ?? "");
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(records),
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/#/rir");

  // Heading + count.
  await expect(
    page.getByRole("heading", { name: /RIR records/i }),
  ).toBeVisible();

  // inet[6]num headline collapses to the /24 CIDR (no
  // ``— stop`` form); badges surface country and netname.
  await expect(page.getByText("192.0.2.0/24")).toBeVisible();
  await expect(page.getByText(/netname:.*EXAMPLE-NET/i)).toBeVisible();

  // aut-num headline.
  await expect(page.getByRole("button", { name: /^AS64512$/ })).toBeVisible();
  await expect(page.getByText(/as-name:.*EXAMPLE-AS/i)).toBeVisible();

  // The "Show more" toggle reveals the extra RPSL fields
  // (``mnt-by``, ``status``) that aren't in the visible badges.
  const showMore = page.getByRole("button", { name: /show more/i }).first();
  await showMore.click();
  await expect(page.getByText("mnt-by:")).toBeVisible();
  await expect(page.getByText("EXAMPLE-MNT")).toBeVisible();

  // The endpoint received the user's (empty) ``q``.
  expect(queries.length).toBeGreaterThan(0);
  expect(queries[0]).toBe("");
});

test("RIR section forwards user-typed filters to /cgi/rir", async ({
  page,
}) => {
  const queries: string[] = [];
  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/rir") {
      queries.push(url.searchParams.get("q") ?? "");
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: "[]",
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/#/rir?q=country%3AFR");
  await page.waitForLoadState("networkidle");

  expect(queries.length).toBeGreaterThan(0);
  expect(queries[queries.length - 1]).toBe("country:FR");
});

test("WEB_MODULES allowlist hides disabled sections from the nav", async ({
  page,
}) => {
  // ``/cgi/config`` sets ``config.modules = [...]``: only the
  // listed sections are exposed by the server, and the React UI
  // must filter the nav accordingly. Going directly to a
  // disabled section's URL falls through to ``<SectionStub />``
  // with the "not exposed" message.
  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/config") {
      return route.fulfill({
        status: 200,
        contentType: "application/javascript",
        body: 'config.modules = ["view", "active"];\n',
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/");

  const sectionNav = page.locator("header nav").first();
  // Only the two enabled sections appear in the nav.
  await expect(sectionNav.getByRole("link", { name: "View" })).toBeVisible();
  await expect(sectionNav.getByRole("link", { name: "Active" })).toBeVisible();
  // The four disabled ones (Passive / DNS / RIR / Flow) must NOT
  // be in the nav.
  await expect(sectionNav.getByRole("link", { name: "Passive" })).toHaveCount(
    0,
  );
  await expect(sectionNav.getByRole("link", { name: "DNS" })).toHaveCount(0);
  await expect(sectionNav.getByRole("link", { name: "RIR" })).toHaveCount(0);
  await expect(sectionNav.getByRole("link", { name: "Flow" })).toHaveCount(0);

  // Direct navigation to a disabled section reaches the stub
  // with the "not exposed" copy (a different message from the
  // generic "under construction" one used for sections that are
  // enabled but not yet implemented, e.g. flow on master).
  await page.goto("/#/passive");
  await expect(page.getByText(/not exposed on this server/i)).toBeVisible();
});

test("WEB_MODULES absent on /cgi/config keeps every section visible (back-compat)", async ({
  page,
}) => {
  // Older server: ``/cgi/config`` doesn't emit a ``modules``
  // field. The React UI must keep showing every section
  // unconditionally (otherwise upgrading the bundle without
  // upgrading the server would drop the nav).
  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/config") {
      return route.fulfill({
        status: 200,
        contentType: "application/javascript",
        // No ``config.modules = [...]`` line — mimics an older
        // server that has not yet learned about ``WEB_MODULES``.
        body: "config.auth_enabled = false;\n",
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/");
  const sectionNav = page.locator("header nav").first();
  for (const label of ["View", "Active", "Passive", "DNS", "RIR", "Flow"]) {
    await expect(sectionNav.getByRole("link", { name: label })).toBeVisible();
  }
});

test("Flow section renders the graph + counts and forwards filters as JSON q=", async ({
  page,
}) => {
  // The /cgi/flows route takes a JSON-encoded q= and returns
  // either a graph (default) or a counts object (q.count =
  // true). The route makes both calls per refresh; mock both
  // shapes and capture the queries to assert the dual-textarea
  // serialises through to q.nodes / q.edges.
  const graphPayload = {
    nodes: [
      {
        id: "10.0.0.1",
        label: "10.0.0.1",
        labels: ["Host"],
        x: 0.1,
        y: 0.2,
        data: { addr: "10.0.0.1" },
      },
      {
        id: "10.0.0.2",
        label: "10.0.0.2",
        labels: ["Host"],
        x: 0.7,
        y: 0.8,
        data: { addr: "10.0.0.2" },
      },
    ],
    edges: [
      {
        id: "edge-1",
        label: "tcp/443",
        labels: ["Flow"],
        source: "10.0.0.1",
        target: "10.0.0.2",
        data: { proto: "tcp", dport: 443, count: 5 },
      },
    ],
  };
  const countsPayload = { clients: 1, servers: 1, flows: 5 };
  const captured: Array<{ q: string; count: boolean }> = [];

  await page.route("**/cgi/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/cgi/flows") {
      const qRaw = url.searchParams.get("q") ?? "{}";
      const q = JSON.parse(qRaw) as { count?: boolean };
      captured.push({ q: qRaw, count: q.count === true });
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(q.count === true ? countsPayload : graphPayload),
      });
    }
    return route.fulfill({ status: 204 });
  });

  await page.goto("/#/flow");

  // Heading + counts header rendered. The filter panel is
  // rendered twice (desktop aside + lg:hidden mobile fallback),
  // so scope assertions on the panel content to the desktop
  // aside to avoid strict-mode multi-match.
  await expect(
    page.getByRole("heading", { name: /Flow graph/i }),
  ).toBeVisible();
  const aside = page.locator("aside").first();
  await expect(aside.getByText("Clients")).toBeVisible();
  await expect(aside.getByText("Servers")).toBeVisible();
  await expect(aside.getByText("Flows", { exact: true })).toBeVisible();

  // Graph canvas is mounted with the expected accessible label.
  await expect(
    page.getByLabel(/Flow graph \(2 nodes, 1 edges\)/i),
  ).toBeVisible();

  // The route fired both shapes (graph + counts).
  expect(captured.length).toBeGreaterThanOrEqual(2);
  expect(captured.some((c) => c.count === false)).toBe(true);
  expect(captured.some((c) => c.count === true)).toBe(true);

  // Pin: every initial request carries an explicit ``skip: 0``
  // so the page renders correctly against older servers whose
  // ``/cgi/flows`` route defaulted ``skip`` to
  // ``WEB_GRAPH_LIMIT`` (a copy-paste bug \u2014 the route now
  // defaults to 0, but old deployments still need this client
  // workaround).
  for (const cap of captured) {
    const parsed = JSON.parse(cap.q) as { skip?: number };
    expect(parsed.skip).toBe(0);
  }

  // Type a node filter, hit Apply, assert the next graph
  // request carries it in q.nodes. Scope the textbox / button
  // lookups to the visible (desktop) aside.
  const before = captured.length;
  await aside
    .getByRole("textbox", { name: /node filters/i })
    .fill("addr =~ 10.0.0.0/24");
  await aside.getByRole("button", { name: /^Apply$/ }).click();
  await page.waitForLoadState("networkidle");
  expect(captured.length).toBeGreaterThan(before);
  const latest = JSON.parse(captured[captured.length - 1].q) as {
    nodes?: string[];
  };
  expect(latest.nodes).toEqual(["addr =~ 10.0.0.0/24"]);
});
