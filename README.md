# Security Guard Worker

Cloudflare Worker that receives security alerts and CSP violation reports, then sends email notifications via SendGrid.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/alert` | Receive security alerts from client-side interceptors |
| POST | `/csp-report` | Receive CSP violation reports from browser |

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Set SendGrid API key:
   ```bash
   wrangler secret put SENDGRID_API_KEY
   ```

3. Configure app registry in `wrangler.toml`:
   ```toml
   APP_MY_APP_EMAIL = "alerts@mycompany.com"
   ```

4. Deploy:
   ```bash
   npm run deploy
   ```

## Development

```bash
npm run dev
```

## Usage

### From JavaScript/TypeScript

```typescript
// Report security alert
fetch('https://guard-worker.<account>.workers.dev/alert', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    appName: 'my_app',
    type: 'unauthorized_fetch',
    url: 'https://blocked-domain.com/api',
    hostname: 'blocked-domain.com',
    timestamp: Date.now(),
    appVersion: '1.0.0',
  }),
});
```

### CSP Report URI

In your CSP header or manifest.json:
```
report-uri https://guard-worker.<account>.workers.dev/csp-report?appName=my_app
```

## Adding New Apps

Add a new environment variable in `wrangler.toml`:

```toml
APP_NEW_APP_EMAIL = "team@newapp.com"
```

The app name in requests should match (case-insensitive, hyphens become underscores):
- `new_app` or `new-app` → `APP_NEW_APP_EMAIL`
