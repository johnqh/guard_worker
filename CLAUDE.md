# guard_worker - AI Development Guide

> **Git policy — never auto-commit or auto-push.** Leave your work in the working tree.
> Run `git commit`, `git push`, `gh pr create`, or `scripts/push_all.sh` **only when the user
> explicitly asks in that turn**. Approval for an earlier change does not carry forward, and
> finishing a task is not permission to commit it. Stay on the current branch (no feature branches).

## What it is

A Cloudflare Worker that receives security alerts and CSP violation reports from
client-side apps and sends formatted HTML email notifications via the SendGrid v3
API. Recipients are resolved from a per-app registry in `wrangler.toml`.

- **Stack**: TypeScript (ES2022, strict), Cloudflare Workers native `fetch` handler (no framework), SendGrid for email.
- **Package manager**: Bun. **License**: BUSL-1.1, `private: true` (not published to npm).
- **No runtime dependencies** — only devDependencies (wrangler, vitest, typescript, eslint, prettier).

## Commands (all verified)

```bash
bun install
bun run dev            # wrangler dev (local server)
bun run deploy         # wrangler deploy
bun run tail           # live production logs
bun run test:unit      # vitest run  (NOTE: there is no `bun run test`)
bun run test:watch     # vitest watch
bun run typecheck      # tsc --noEmit
bun run lint           # eslint src/   (lint:fix to autofix)
bun run format         # prettier --write   (format:check to verify)
bun run verify         # typecheck + test:unit — run this before deploying
wrangler secret put SENDGRID_API_KEY   # set the SendGrid secret
```

## Layout

```
src/index.ts        # Worker entry: fetch handler, routing, handlers, validation, SendGrid
src/email.ts        # SecurityAlert interface, VALID_ALERT_TYPES, formatSecurityAlertEmail(), escapeHtml()
src/index.test.ts   # Worker/routing tests (vitest, mocks global.fetch)
src/email.test.ts   # Email formatting + escaping tests
wrangler.toml       # Worker config, [vars] app registry, FROM_EMAIL
eslint.config.js    # flat config; type-aware, ignores *.test.ts
plans/IMPROVEMENTS.md  # backlog (many items already done ✅)
```

## Architecture

Single `fetch(request, env)` export. Request flow: OPTIONS→CORS; non-POST→405;
`Content-Length` > 100 KB → 413; then path routing.

| Path | Handler | Returns |
|------|---------|---------|
| `/alert`, `/security-alert` | `handleSecurityAlert` | `{ success }` JSON, 200/400/500 |
| `/csp-report` | `handleCspReport` | **always 204** (even on unknown app / send failure) |
| other | — | 404 |

- **App registry**: `getRecipientEmail()` normalizes `appName` (uppercase, `-`→`_`)
  and looks up `env["APP_<NAME>_EMAIL"]`. Registered: `mail_box`, `mail_box_wallet`.
- **Validation**: `validateAlertPayload()` requires `appName` (non-empty string),
  `type` ∈ `VALID_ALERT_TYPES`, `url`/`hostname` strings, `timestamp` number;
  returns 400 on failure.
- **CSP inference**: `inferAppName()` maps `signic.email` → `mail_box`,
  `chrome-extension:` → `mail_box_wallet` when `?appName=` is absent.
- **Email**: `formatSecurityAlertEmail()` builds a full HTML doc with inline CSS;
  every user value passes through `escapeHtml()`. Sent by `sendEmail()` as
  `Security Guard <FROM_EMAIL>`.

## Env (`interface Env`)

- `SENDGRID_API_KEY` — secret (`wrangler secret put`); local dev reads `.dev.vars`.
- `FROM_EMAIL` — sender address, set in `wrangler.toml` `[vars]`.
- `APP_<NAME>_EMAIL` — dynamic registry entries (index signature).

## Conventions & invariants

- Workers runtime only — Web APIs, **no Node.js built-ins**.
- All user-supplied values in email HTML **must** go through `escapeHtml()` (XSS).
- Every response includes the `corsHeaders` constant.
- `SecurityAlert` type and `VALID_ALERT_TYPES` live in `src/email.ts` — import from there, keep them in sync when adding alert types.
- Adding an app: add `APP_<NAME>_EMAIL` to `wrangler.toml` `[vars]`, extend
  `createMockEnv()` in `src/index.test.ts`, optionally add an `inferAppName()` rule.

## Gotchas

- **No `test` script** — the test command is `bun run test:unit` (not `test`).
- **CSP reports always 204** — never surface errors to the browser on `/csp-report`.
- **`compatibility_date = 2024-12-30`** pins runtime behavior; change deliberately.
- **No DOM/Node types** — tsconfig `types` is only `@cloudflare/workers-types`.
- `bun install` uses GitHub Packages for `@sudobility:*` (see `.npmrc`).
