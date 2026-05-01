# IVRE web-ui

This directory holds the React workspace that will replace the legacy
AngularJS UI under `web/static/`.

It is **not** wired into `ivre httpd` yet: it builds to `web-ui/dist/`
and is meant to be served either by a development server (`pnpm dev`,
which proxies `/cgi/` to the IVRE backend) or, eventually, by the same
nginx that serves the legacy assets.

## Stack

- [pnpm](https://pnpm.io/) for package management (Node ≥ 20.19).
- [Vite](https://vitejs.dev/) + [React 19](https://react.dev/).
- [TypeScript 5](https://www.typescriptlang.org/) (strict, project
  references for app vs. tooling).
- [Tailwind CSS 4](https://tailwindcss.com/) via the `@tailwindcss/vite`
  plugin.
- [shadcn/ui](https://ui.shadcn.com/) ("new-york" style, neutral
  palette). Components are copied into `src/components/ui/` so we own
  the source.
- [Vitest](https://vitest.dev/) + [Testing Library](https://testing-library.com/)
  for unit/component tests, in `jsdom`.
- [Playwright](https://playwright.dev/) for end-to-end smoke tests.
- [ESLint 9](https://eslint.org/) flat config with TypeScript + React
  Hooks rules.

## Layout

```
web-ui/
├── eslint.config.js          ESLint flat config
├── index.html                Vite entry HTML
├── package.json              dependencies and scripts
├── playwright.config.ts      Playwright config (chromium-only)
├── tsconfig*.json            TypeScript project references
├── vite.config.ts            Vite (build + dev server + proxy)
├── vitest.config.ts          Vitest (unit tests)
├── components.json           shadcn/ui CLI config
├── src/
│   ├── App.tsx               root component (placeholder)
│   ├── App.test.tsx          Vitest unit test
│   ├── components/ui/        shadcn-managed components
│   ├── index.css             Tailwind v4 + shadcn tokens
│   ├── lib/utils.ts          shadcn `cn()` helper
│   ├── main.tsx              React 19 entry
│   └── test/setup.ts         testing-library setup
└── e2e/
    └── smoke.spec.ts         Playwright smoke test
```

## Running

```sh
# install dependencies (uses pnpm-lock.yaml for reproducible installs)
pnpm install

# start the dev server with HMR (proxies /cgi/ to localhost:9000)
pnpm dev

# build for production
pnpm build
pnpm preview                     # serve the dist/ output

# unit tests
pnpm test                        # one-shot
pnpm test:watch                  # watch mode

# end-to-end tests (downloads chromium on first run)
pnpm exec playwright install chromium
pnpm test:e2e

# lint and type-check
pnpm lint
pnpm typecheck
```

## Backend URL

`pnpm dev` expects an IVRE backend reachable at `http://localhost:9000`
by default. Override with `VITE_BACKEND_URL`:

```sh
VITE_BACKEND_URL=http://10.0.0.5:80 pnpm dev
```

The proxy is dev-only; production builds are static and assume the
backend is mounted at `/cgi/` on the same origin.

## Adding shadcn/ui components

```sh
pnpm dlx shadcn@latest add <component>
```

The CLI uses `components.json` to drop new components into
`src/components/ui/`.

## Building the deployable bundle

The deployed artefact lives under `web/static/ui/`. It is regenerated
by `pkg/buildwebui` (a thin wrapper around `pnpm install --frozen-lockfile`
and `pnpm build`) and shipped via `setup.py` as `data_files`.

```sh
./pkg/buildwebui
```

Run this whenever sources under `web-ui/` change, and commit the
regenerated `web/static/ui/` tree in the same commit as the source
change. Keep the two in lockstep; do not split them across commits.

**Never edit `web/static/ui/**` by hand.** Any manual change is
overwritten on the next build, and the review diff becomes
unreadable. (Same rule as `web/static/doc/`, regenerated from `doc/`
by `pkg/builddocs`.)

## Air-gapped deployment

The deployed bundle under `web/static/ui/` makes **no external HTTP
requests at runtime**:

- No CDN scripts or stylesheets in `index.html`.
- No Google Fonts (only `system-ui` + the standard system-font
  fallback chain).
- No analytics, no telemetry, no crash reporters.
- No `@import url(https://...)` in CSS.
- All dependencies (React, Tailwind utilities, shadcn components,
  lucide-react, Radix primitives, …) are bundled into a single
  `assets/index-<hash>.js` and `assets/index-<hash>.css` at build
  time.

A CI step (`Verify the bundle is self-contained` in
`.github/workflows/web-ui.yml`) greps the built bundle for any
unexpected `https?://` URLs and fails the build if it finds them. The
allowed strings are XML/SVG namespaces (`www.w3.org/...`),
`localhost*` (dev-only proxy targets that should never appear in the
production bundle), `react.dev/errors/...` (React's error-code
lookup, a constructed string in console output, never fetched at
runtime), and `tailwindcss.com` (license attribution comment in the
generated CSS).

**Build-time tools do require internet access:**

- `pnpm install` fetches packages from the npm registry.
- The Vite plugin for Tailwind (`@tailwindcss/vite`) pulls a native
  `oxide` binary the first time it runs.
- `pnpm exec playwright install chromium` downloads browser
  binaries.

Recommended workflow for air-gapped deployers: build on a connected
machine (`./pkg/buildwebui` followed by `python -m build`), then ship
the resulting wheel — it contains the pre-built `web/static/ui/`
tree.

The legacy `/cgi/config` route emits `fetch("https://ivre.rocks/version?...")`
to surface upgrade hints in the Web UI; the call is best-effort and
its failure is silently swallowed by the legacy AngularJS client.
The new web-ui does not yet consume `/cgi/config`; when it does, an
opt-out for the upstream version check will be added so that
air-gapped operators can disable it explicitly.
