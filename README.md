# Security Guard Worker

Cloudflare Worker that receives security alerts and CSP (Content Security Policy)
violation reports from client-side applications, then sends formatted HTML email
notifications to the appropriate team via the SendGrid API. Alerts are routed to
recipients using a per-app registry configured in `wrangler.toml`.

- **Runtime**: Cloudflare Workers (native `fetch` handler, no framework)
- **Language**: TypeScript (ES2022, strict)
- **Package manager**: Bun
- **Email delivery**: SendGrid v3 API

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/alert` | Receive security alerts from client-side interceptors |
| POST | `/security-alert` | Alias for `/alert` |
| POST | `/csp-report` | Receive CSP violation reports from the browser |
| OPTIONS | `*` | CORS preflight (returns CORS headers) |

All responses include permissive CORS headers (`Access-Control-Allow-Origin: *`).
Non-POST requests to other paths return 405; unknown paths return 404. Request
bodies larger than 100 KB are rejected with 413.

## Setup

1. Install dependencies:
   ```bash
   bun install
   ```

2. Set the SendGrid API key (a secret, not stored in `wrangler.toml`):
   ```bash
   wrangler secret put SENDGRID_API_KEY
   ```

3. Configure the app registry in `wrangler.toml` under `[vars]`
   (see "Adding New Apps" below).

4. Deploy:
   ```bash
   bun run deploy
   ```

## Development

```bash
bun run dev            # Start local dev server (wrangler dev)
bun run test:unit      # Run tests once (vitest run)
bun run test:watch     # Run tests in watch mode
bun run typecheck      # Type-check with tsc --noEmit
bun run lint           # Lint src/ with ESLint
bun run format         # Format src/ with Prettier
bun run verify         # typecheck + test:unit (run before deploying)
bun run tail           # View real-time production logs
```

For local development, put secrets in a gitignored `.dev.vars` file:

```
SENDGRID_API_KEY=SG.xxxxx
```

## Usage

### Reporting a security alert

```typescript
fetch('https://guard-worker.<account>.workers.dev/alert', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    appName: 'mail_box',
    type: 'unauthorized_fetch', // or unauthorized_xhr | unauthorized_websocket | csp_violation
    url: 'https://blocked-domain.com/api',
    hostname: 'blocked-domain.com',
    timestamp: Date.now(),
    appVersion: '1.0.0', // optional
    // optional: stack, userAgent, metadata
  }),
});
```

Required fields: `appName` (non-empty string), `type` (one of the four values
above), `url` (string), `hostname` (string), `timestamp` (number). Invalid
payloads return 400 with an error message. Unknown apps return 400.

### CSP report URI

In your CSP header or extension manifest:

```
report-uri https://guard-worker.<account>.workers.dev/csp-report?appName=mail_box
```

When `appName` is omitted, the worker infers it from the report's `document-uri`:
`signic.email` hostnames map to `mail_box`, and `chrome-extension:` URIs map to
`mail_box_wallet`. CSP endpoints always respond 204, even on unknown apps or
send failures (browsers expect this).

## Adding New Apps

Add an environment variable in `wrangler.toml` under `[vars]`:

```toml
APP_NEW_APP_EMAIL = "team@newapp.com"
```

The `appName` in requests is normalized (uppercased, hyphens become
underscores) and looked up as `APP_<NAME>_EMAIL`, so `new_app`, `new-app`, and
`New_App` all resolve to `APP_NEW_APP_EMAIL`. Optionally add a rule in
`inferAppName()` (`src/index.ts`) for automatic CSP report routing.

Currently registered: `mail_box` and `mail_box_wallet` (both →
`support@sudobility.com`).
