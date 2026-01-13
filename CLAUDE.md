# CLAUDE.md - AI Assistant Guide

This file provides guidance for AI assistants working with this repository.

## Project Overview

`guard_worker` is a Cloudflare Worker that receives security alerts and CSP violation reports, then sends email notifications via SendGrid.

**Type**: Cloudflare Worker (TypeScript)
**Private**: Yes (not published to npm)

## Package Manager

**This project uses Bun for dependency management.** Use `bun` for installing packages:

```bash
# Install dependencies
bun install
```

## Development Commands

```bash
# Development server (local)
bun run dev
# or: wrangler dev

# Deploy to Cloudflare
bun run deploy
# or: wrangler deploy

# View real-time logs
bun run tail
# or: wrangler tail
```

## Project Structure

```
src/
└── index.ts          # Main worker entry point
wrangler.toml         # Cloudflare Worker configuration
tsconfig.json         # TypeScript configuration
```

## Architecture

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/alert` | Receive security alerts from client-side interceptors |
| POST | `/csp-report` | Receive CSP violation reports from browser |

### Dependencies

- `@cloudflare/workers-types` - Cloudflare Worker TypeScript types
- `wrangler` - Cloudflare CLI for development and deployment

### Configuration

Environment variables are configured in `wrangler.toml`:
- `SENDGRID_API_KEY` - Secret for SendGrid email API (set via `wrangler secret put`)
- `APP_<APP_NAME>_EMAIL` - Email recipients for each app

## Development Guidelines

### Adding New Apps

Add a new environment variable in `wrangler.toml`:
```toml
APP_NEW_APP_EMAIL = "team@newapp.com"
```

The app name in requests should match (case-insensitive, hyphens become underscores):
- `new_app` or `new-app` -> `APP_NEW_APP_EMAIL`

### Setting Secrets

```bash
wrangler secret put SENDGRID_API_KEY
```

### Alert Payload Format

```typescript
interface SecurityAlert {
  appName: string;
  type: string;
  url: string;
  hostname: string;
  timestamp: number;
  appVersion: string;
}
```

## AI Assistant Instructions

### Quick Start

1. **Read this file first** - Contains project context
2. **Check `src/index.ts`** - Main worker logic
3. **Check `wrangler.toml`** - Configuration and secrets
4. **Test locally** - Run `bun run dev` before deploying

### Common Tasks

**Adding a new endpoint**:
1. Add route handling in `src/index.ts`
2. Test locally with `bun run dev`
3. Deploy with `bun run deploy`

**Adding a new app for alerts**:
1. Add `APP_<APP_NAME>_EMAIL` to `wrangler.toml`
2. Deploy with `bun run deploy`

### Project Invariants

1. **Cloudflare Worker runtime** - Use Web Workers API, no Node.js modules
2. **SendGrid for email** - All notifications go through SendGrid
3. **Private project** - Not published to npm
