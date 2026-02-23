# guard_worker - Improvement Plans

## Priority 1: Code Quality

### 1.1 Add `userAgent` to email template
- **File**: `src/index.ts`
- **Issue**: The `SecurityAlert` interface accepts a `userAgent` field, but `formatSecurityAlertEmail()` does not render it. The data is silently discarded.
- **Fix**: Add a conditional field in the email template for `userAgent`, similar to how `appVersion` is handled.

### 1.2 Add lint and typecheck scripts
- **File**: `package.json`
- **Issue**: Unlike other projects in the ecosystem, there are no `lint`, `typecheck`, or `verify` scripts. TypeScript checking only happens implicitly during `wrangler dev` or `wrangler deploy`.
- **Fix**: Add scripts: `"typecheck": "tsc --noEmit"`, `"lint": "eslint src/"`, `"verify": "bun run typecheck && bun run test"`. Add ESLint as a dev dependency.

### 1.3 Extract email template to separate module
- **File**: `src/index.ts`
- **Issue**: The single-file architecture makes the HTML email template hard to maintain. The template string is ~50 lines of HTML mixed with TypeScript logic.
- **Fix**: Consider extracting `formatSecurityAlertEmail()` and `escapeHtml()` to a `src/email.ts` module. This preserves the simple architecture while improving maintainability.

## Priority 2: Reliability

### 2.1 Add request body size limit
- **Issue**: No limit on incoming request body size. A malicious actor could send extremely large payloads.
- **Fix**: Add a check on `Content-Length` header or read the body with a size limit before parsing JSON.

### 2.2 Add rate limiting
- **Issue**: No rate limiting on alert or CSP report endpoints. A misconfigured client or attacker could flood the worker with requests, consuming SendGrid quota.
- **Fix**: Use Cloudflare's Rate Limiting or a simple in-memory counter with KV storage to limit requests per app per time window.

### 2.3 Validate alert payload structure
- **File**: `src/index.ts`
- **Issue**: `handleSecurityAlert()` casts the parsed JSON directly to `SecurityAlert` without validation. Missing or malformed fields (e.g., non-string `url`, missing `timestamp`) could cause unexpected behavior.
- **Fix**: Add runtime validation for required fields (appName, type, url, hostname, timestamp) with appropriate error responses.

### 2.4 Handle SendGrid quota exhaustion gracefully
- **Issue**: If SendGrid returns a 429 (rate limit) response, the worker treats it the same as any other failure. No retry or backoff logic exists.
- **Fix**: Detect 429 responses specifically and either queue the email for retry (using Cloudflare Queues or Durable Objects) or log it for manual follow-up.

## Priority 3: Observability

### 3.1 Add structured logging
- **Issue**: Console logging is minimal and unstructured. In production, it is difficult to trace request flows or aggregate error counts.
- **Fix**: Add structured JSON logging with consistent fields: `{ event, appName, path, status, duration }`.

### 3.2 Add metrics/analytics
- **Issue**: No tracking of alert volume, types, or apps. There is no visibility into how many alerts are being processed.
- **Fix**: Consider using Cloudflare Workers Analytics Engine or sending metrics to an external service. Track: alerts per app, alert types, email success/failure rates.

### 3.3 Add request ID tracking
- **Issue**: No correlation ID exists for tracing a request from alert ingestion to email delivery.
- **Fix**: Generate a UUID for each request and include it in log messages and email headers.

## Priority 4: Feature Enhancements

### 4.1 Support batch alerts
- **Issue**: Each alert requires a separate HTTP request and generates a separate email. High-volume scenarios could benefit from batching.
- **Fix**: Add a `/alerts` (plural) endpoint that accepts an array of alerts and sends a single summary email.

### 4.2 Add alert deduplication
- **Issue**: The same alert (same app, type, URL) can be sent multiple times. If a client-side interceptor fires rapidly, it generates duplicate emails.
- **Fix**: Use Cloudflare KV or Cache API to track recent alerts and suppress duplicates within a configurable time window (e.g., 5 minutes).

### 4.3 Support webhook delivery in addition to email
- **Issue**: Email is the only notification channel. Teams using Slack, Discord, or PagerDuty cannot receive alerts directly.
- **Fix**: Add an optional `APP_<APPNAME>_WEBHOOK` environment variable. When present, send a JSON payload to the webhook URL in addition to (or instead of) email.

### 4.4 Add health check endpoint
- **Issue**: No way to verify the worker is running and configured correctly without sending a real alert.
- **Fix**: Add a `GET /health` endpoint that returns `{ status: "ok", apps: [...] }` with the list of registered apps (without exposing email addresses).

## Priority 5: Testing

### 5.1 Add SendGrid response body assertion
- **Issue**: Tests mock `global.fetch` but do not assert the exact request body sent to SendGrid (email content, from address, subject format).
- **Fix**: Add assertions on the `fetch` mock's call arguments to verify the SendGrid API payload structure.

### 5.2 Add email template snapshot tests
- **Issue**: No tests verify the HTML output of `formatSecurityAlertEmail()`. Template changes could introduce formatting issues or XSS vulnerabilities.
- **Fix**: Add snapshot tests that capture the HTML output for various alert types and verify `escapeHtml()` is applied to all user-supplied fields.
