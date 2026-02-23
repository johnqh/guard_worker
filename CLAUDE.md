# guard_worker - AI Development Guide

## Overview

`guard_worker` is a Cloudflare Worker that receives security alerts and CSP (Content Security Policy) violation reports from client-side applications, then sends formatted HTML email notifications to the appropriate team via the SendGrid API. It acts as a centralized security monitoring endpoint for multiple apps, routing alerts based on a configurable app registry.

- **Package name**: `guard_worker`
- **Version**: `1.0.2`
- **License**: Private (not published to npm)
- **Package manager**: Bun (`bun install`, `bun run <script>`)

## Project Structure

```
guard_worker/
├── src/
│   ├── index.ts            # Main worker entry point (all logic in single file)
│   └── index.test.ts       # Vitest test suite
├── wrangler.toml            # Cloudflare Worker config, app registry, env vars
├── tsconfig.json            # TypeScript config (ES2022, strict, Cloudflare types)
├── package.json             # Scripts and dev dependencies
├── bun.lock                 # Bun lockfile
├── .gitignore               # Ignores node_modules/, dist/, .wrangler/, .dev.vars
├── CLAUDE.md                # This file
└── README.md                # User-facing documentation
```

## Key Components

### App Registry

Apps are registered via environment variables in `wrangler.toml` using the pattern `APP_<APPNAME>_EMAIL`. The worker resolves recipient emails by normalizing the incoming `appName` (uppercasing, replacing hyphens with underscores) and looking up `APP_<NORMALIZED>_EMAIL` in the environment.

Currently registered apps:
- `mail_box` -> `APP_MAIL_BOX_EMAIL` -> `support@sudobility.com`
- `mail_box_wallet` -> `APP_MAIL_BOX_WALLET_EMAIL` -> `support@sudobility.com`

The `inferAppName()` function also provides automatic app detection for CSP reports:
- URLs containing `signic.email` are mapped to `mail_box`
- `chrome-extension:` protocol URIs are mapped to `mail_box_wallet`

### Routing

Manual path-based routing (no framework -- uses native `Request`/`URL` APIs):

| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| OPTIONS | `*` | CORS preflight | Returns CORS headers (`Access-Control-Allow-Origin: *`) |
| POST | `/alert` | `handleSecurityAlert()` | Receives security alerts from client-side interceptors |
| POST | `/security-alert` | `handleSecurityAlert()` | Alias for `/alert` |
| POST | `/csp-report` | `handleCspReport()` | Receives browser CSP violation reports |
| * | `*` | 404 / 405 | Unknown paths or non-POST methods |

### Email Formatting

`formatSecurityAlertEmail()` generates a styled HTML email with:
- Red header banner with alert type
- Fields: Application, Date & Time, Blocked URL, Hostname
- Conditional fields: App Version, Stack Trace, Additional Details (metadata)
- All user-supplied strings are sanitized via `escapeHtml()` to prevent XSS

Emails are sent through `sendEmail()` which calls the SendGrid v3 API (`https://api.sendgrid.com/v3/mail/send`). The sender identity is `Security Guard <security@sudobility.com>`.

### Core Interfaces

```typescript
interface SecurityAlert {
  appName: string;
  type: 'unauthorized_fetch' | 'unauthorized_xhr' | 'unauthorized_websocket' | 'csp_violation';
  url: string;
  hostname: string;
  timestamp: number;
  stack?: string;
  appVersion?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}

interface CspReport {
  'csp-report': {
    'document-uri': string;
    'violated-directive': string;
    'blocked-uri': string;
    'original-policy'?: string;
    'source-file'?: string;
    'line-number'?: number;
  };
}

interface Env {
  SENDGRID_API_KEY: string;       // Secret, set via wrangler secret put
  FROM_EMAIL: string;             // Sender email address
  [key: string]: string;          // Dynamic APP_<APPNAME>_EMAIL entries
}
```

### Internal Functions

| Function | Purpose |
|----------|---------|
| `handleSecurityAlert(request, env)` | Parses alert JSON, resolves recipient, sends email |
| `handleCspReport(request, env, url)` | Parses CSP report, infers app name, sends email |
| `getRecipientEmail(appName, env)` | Normalizes app name and looks up `APP_<NAME>_EMAIL` |
| `inferAppName(documentUri)` | Heuristic app detection from CSP document URI |
| `extractHostname(urlString)` | Safe hostname extraction with URL parsing fallback |
| `sendEmail(env, options)` | Sends HTML email via SendGrid v3 API |
| `formatSecurityAlertEmail(alert)` | Generates styled HTML email body |
| `escapeHtml(str)` | Escapes `& < > " '` for safe HTML insertion |

## Development Commands

```bash
# Install dependencies
bun install

# Start local development server
bun run dev              # runs: wrangler dev

# Deploy to Cloudflare Workers
bun run deploy           # runs: wrangler deploy

# View real-time production logs
bun run tail             # runs: wrangler tail

# Run tests
bun run test             # runs: vitest run
bun run test:watch       # runs: vitest (watch mode)

# Set secrets
wrangler secret put SENDGRID_API_KEY
```

## Architecture / Patterns

### Cloudflare Worker (No Framework)

This worker uses the native Cloudflare Workers `fetch` handler pattern -- a default export with an `async fetch(request, env)` method. There is no Hono or other routing framework; routing is done via manual `pathname` matching. All logic resides in a single `src/index.ts` file.

### Request Flow

1. CORS preflight check (OPTIONS returns immediately)
2. Method validation (only POST allowed)
3. Path routing to appropriate handler
4. Handler parses JSON body, resolves recipient via app registry
5. Formats HTML email and sends via SendGrid
6. Returns JSON response (`{ success: boolean }`) or 204 for CSP reports

### Error Handling

- Invalid JSON: caught by top-level try/catch, returns 500 with `{ success: false, error: "Internal error" }`
- Missing `appName`: returns 400 with `{ error: "Missing appName" }`
- Unknown app (no matching env var): returns 400 for alerts, 204 for CSP reports
- SendGrid failure: returns 500 with `{ success: false }`
- Missing API key: logs error, returns `success: false`

### CORS

All responses include permissive CORS headers (`Access-Control-Allow-Origin: *`) since alerts are sent from client-side JavaScript in various web apps and browser extensions.

### Testing

Tests use Vitest with mocked `global.fetch` to intercept SendGrid API calls. The test file (`src/index.test.ts`) covers:
- CORS preflight handling
- Security alert validation and routing
- CSP report handling with query param and inferred app names
- Error handling (invalid JSON, SendGrid failures, missing API key)
- App name normalization (hyphens, mixed case)

### TypeScript Configuration

- Target: ES2022, Module: ESNext
- Module resolution: bundler
- Strict mode enabled
- Types: `@cloudflare/workers-types` (no DOM or Node.js types)
- `noEmit: true` (Wrangler handles bundling)
- `isolatedModules: true` for compatibility with bundlers

## Common Tasks

### Adding a New App

1. Add an environment variable in `wrangler.toml` under `[vars]`:
   ```toml
   APP_MY_NEW_APP_EMAIL = "team@example.com"
   ```
2. The app name in requests should match (case-insensitive, hyphens become underscores):
   - `my_new_app`, `my-new-app`, or `My_New_App` all resolve to `APP_MY_NEW_APP_EMAIL`
3. (Optional) If the app has a predictable domain, add a rule in `inferAppName()` for automatic CSP report routing.
4. Add corresponding test entries in `src/index.test.ts` with the new app in `createMockEnv()`.
5. Deploy with `bun run deploy`.

### Modifying Email Templates

1. Edit the `formatSecurityAlertEmail()` function in `src/index.ts`.
2. The function returns a full HTML document string with inline CSS.
3. All dynamic values must be passed through `escapeHtml()` to prevent injection.
4. Test locally with `bun run dev` and send a test POST to `/alert`.

### Adding a New Endpoint

1. Add a new path check in the `fetch()` handler's routing block in `src/index.ts`.
2. Create a handler function following the pattern of `handleSecurityAlert()` or `handleCspReport()`.
3. Include CORS headers in all responses via the `corsHeaders` constant.
4. Add tests in `src/index.test.ts`.
5. Test locally, then deploy.

### Setting / Updating Secrets

```bash
# Set or update the SendGrid API key
wrangler secret put SENDGRID_API_KEY

# For local development, create a .dev.vars file (gitignored):
# SENDGRID_API_KEY=SG.xxxxx
```

## Key Dependencies

### Dev Dependencies (no runtime dependencies)

| Package | Version | Purpose |
|---------|---------|---------|
| `@cloudflare/workers-types` | ^4.20241230.0 | TypeScript type definitions for Cloudflare Worker APIs |
| `typescript` | ^5.7.2 | TypeScript compiler (noEmit -- bundled by Wrangler) |
| `vitest` | ^3.2.4 | Test framework |
| `wrangler` | ^3.99.0 | Cloudflare CLI for local dev, deployment, and secret management |

### External Services

| Service | Usage |
|---------|-------|
| **SendGrid** (v3 API) | Sends HTML email notifications; requires `SENDGRID_API_KEY` secret |
| **Cloudflare Workers** | Hosting platform; configured via `wrangler.toml` |

## Project Invariants

1. **Cloudflare Worker runtime** -- Use Web Workers API only; no Node.js built-in modules.
2. **Single-file architecture** -- All worker logic lives in `src/index.ts`.
3. **SendGrid for email delivery** -- All notifications go through the SendGrid v3 API.
4. **HTML escaping required** -- All user-supplied values in email templates must pass through `escapeHtml()`.
5. **CORS on all responses** -- Every response must include the `corsHeaders` for cross-origin compatibility.
6. **Private project** -- Not published to npm; `"private": true` in package.json.

## Gotchas

- **No `verify` script** -- Unlike other projects, there is no `bun run verify`. Run `bun run test` before deploying.
- **No lint or typecheck scripts** -- TypeScript checking is done implicitly by Wrangler during dev/deploy.
- **`userAgent` field in SecurityAlert is accepted but not displayed** -- The field exists in the interface but `formatSecurityAlertEmail()` does not render it.
- **CSP reports always return 204** -- Even when the app is unknown or email sending fails, CSP reports return 204 (browsers expect this).
- **`compatibility_date` is `2024-12-30`** -- This pins the Cloudflare Workers runtime behavior to that date.
