/**
 * @fileoverview Security Guard Worker - Cloudflare Worker for security alerts.
 *
 * Receives security alerts and CSP (Content Security Policy) violation reports
 * from client-side applications, then sends formatted HTML email notifications
 * to the appropriate team via the SendGrid API. Routes alerts based on a
 * configurable app registry defined in wrangler.toml environment variables.
 */

import {
  formatSecurityAlertEmail,
  VALID_ALERT_TYPES,
  type SecurityAlert,
} from './email';

/** Environment bindings for the Cloudflare Worker. */
interface Env {
  /** SendGrid API key for sending email notifications. Set via `wrangler secret put`. */
  SENDGRID_API_KEY: string;
  /** Sender email address for outbound notifications. */
  FROM_EMAIL: string;
  /** Dynamic app registry: APP_<APPNAME>_EMAIL entries for routing alerts. */
  [key: string]: string;
}

/** CSP violation report payload as sent by browsers. */
interface CspReport {
  'csp-report': {
    /** URI of the document where the violation occurred. */
    'document-uri': string;
    /** The CSP directive that was violated. */
    'violated-directive': string;
    /** URI of the resource that was blocked. */
    'blocked-uri': string;
    /** The full original CSP policy string. */
    'original-policy'?: string;
    /** Source file where the violation occurred. */
    'source-file'?: string;
    /** Line number in the source file. */
    'line-number'?: number;
  };
}

/** Maximum allowed request body size in bytes (100 KB). */
const MAX_REQUEST_BODY_SIZE = 100 * 1024;

// CORS headers for cross-origin requests
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export default {
  /**
   * Main fetch handler for the Cloudflare Worker.
   *
   * Routes incoming requests to the appropriate handler based on HTTP method
   * and URL path. All responses include CORS headers.
   *
   * @param request - The incoming HTTP request.
   * @param env - Environment bindings (secrets and variables from wrangler.toml).
   * @returns HTTP response with JSON body or 204 for CSP reports.
   */
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method !== 'POST') {
      return new Response('Method not allowed', {
        status: 405,
        headers: corsHeaders,
      });
    }

    // Check request body size limit
    const contentLength = request.headers.get('Content-Length');
    if (contentLength && parseInt(contentLength, 10) > MAX_REQUEST_BODY_SIZE) {
      return new Response(
        JSON.stringify({
          success: false,
          error: 'Payload too large',
        }),
        {
          status: 413,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        },
      );
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === '/alert' || path === '/security-alert') {
        return await handleSecurityAlert(request, env);
      }

      if (path === '/csp-report') {
        return await handleCspReport(request, env, url);
      }

      return new Response('Not found', {
        status: 404,
        headers: corsHeaders,
      });
    } catch (error) {
      console.error('Worker error:', error);
      return new Response(
        JSON.stringify({ success: false, error: 'Internal error' }),
        {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        },
      );
    }
  },
};

/**
 * Validate that a value is a non-empty string.
 *
 * @param value - The value to check.
 * @returns True if the value is a string with at least one character.
 */
function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/**
 * Validate a security alert payload at runtime.
 *
 * Checks that all required fields are present and have the correct types.
 *
 * @param payload - The parsed JSON payload to validate.
 * @returns An error message string if invalid, or null if valid.
 */
function validateAlertPayload(payload: Record<string, unknown>): string | null {
  if (!isNonEmptyString(payload.appName)) {
    return 'appName must be a non-empty string';
  }
  if (
    !isNonEmptyString(payload.type) ||
    !VALID_ALERT_TYPES.includes(payload.type as SecurityAlert['type'])
  ) {
    return `type must be one of: ${VALID_ALERT_TYPES.join(', ')}`;
  }
  if (typeof payload.url !== 'string') {
    return 'url must be a string';
  }
  if (typeof payload.hostname !== 'string') {
    return 'hostname must be a string';
  }
  if (typeof payload.timestamp !== 'number') {
    return 'timestamp must be a number';
  }
  return null;
}

/**
 * Handle security alerts from client-side interceptors.
 *
 * Parses the alert JSON body, validates the payload, resolves the recipient
 * email from the app registry, formats an HTML email, and sends it via SendGrid.
 *
 * @param request - The incoming POST request containing a SecurityAlert JSON body.
 * @param env - Environment bindings with app registry and SendGrid credentials.
 * @returns JSON response with `{ success: boolean }` and appropriate status code.
 */
async function handleSecurityAlert(
  request: Request,
  env: Env,
): Promise<Response> {
  const payload: Record<string, unknown> = await request.json();

  const validationError = validateAlertPayload(payload);
  if (validationError) {
    return new Response(
      JSON.stringify({ success: false, error: validationError }),
      {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      },
    );
  }

  const alert = payload as unknown as SecurityAlert;

  const recipient = getRecipientEmail(alert.appName, env);
  if (!recipient) {
    console.warn(`Unknown app: ${alert.appName}`);
    return new Response(
      JSON.stringify({ success: false, error: 'Unknown app' }),
      {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      },
    );
  }

  const emailSent = await sendEmail(env, {
    to: recipient,
    subject: `[Security Alert] ${alert.appName}: ${alert.type}`,
    html: formatSecurityAlertEmail(alert),
  });

  return new Response(JSON.stringify({ success: emailSent }), {
    status: emailSent ? 200 : 500,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

/**
 * Handle CSP violation reports from browser.
 *
 * Parses the CSP report JSON, determines the app name from query params
 * or by inferring from the document URI, then sends an email notification.
 * Always returns 204 as browsers expect this for CSP report endpoints.
 *
 * @param request - The incoming POST request containing a CspReport JSON body.
 * @param env - Environment bindings with app registry and SendGrid credentials.
 * @param url - Parsed URL of the request (for query parameter extraction).
 * @returns 204 No Content response (required by CSP reporting spec).
 */
async function handleCspReport(
  request: Request,
  env: Env,
  url: URL,
): Promise<Response> {
  const report: CspReport = await request.json();
  const cspData = report['csp-report'];

  // Get appName from query param or try to infer from document-uri
  const appName =
    url.searchParams.get('appName') || inferAppName(cspData['document-uri']);

  if (!appName) {
    console.warn('CSP report without appName:', cspData);
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  const recipient = getRecipientEmail(appName, env);
  if (!recipient) {
    console.warn(`Unknown app for CSP report: ${appName}`);
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  const alert: SecurityAlert = {
    appName,
    type: 'csp_violation',
    url: cspData['blocked-uri'],
    hostname: extractHostname(cspData['blocked-uri']),
    timestamp: Date.now(),
    metadata: {
      documentUri: cspData['document-uri'],
      violatedDirective: cspData['violated-directive'],
      originalPolicy: cspData['original-policy'],
      sourceFile: cspData['source-file'],
      lineNumber: cspData['line-number'],
    },
  };

  await sendEmail(env, {
    to: recipient,
    subject: `[CSP Violation] ${appName}: ${cspData['violated-directive']}`,
    html: formatSecurityAlertEmail(alert),
  });

  // CSP reports expect 204 No Content
  return new Response(null, { status: 204, headers: corsHeaders });
}

/**
 * Get recipient email from the app registry.
 *
 * Normalizes the app name by uppercasing and replacing hyphens with underscores,
 * then looks up `APP_<NORMALIZED>_EMAIL` in the environment bindings.
 *
 * @param appName - The application name from the alert payload.
 * @param env - Environment bindings containing APP_*_EMAIL entries.
 * @returns The recipient email address, or undefined if not registered.
 */
function getRecipientEmail(appName: string, env: Env): string | undefined {
  // Normalize app name: mail_box_wallet -> MAIL_BOX_WALLET
  const normalizedName = appName.toUpperCase().replace(/-/g, '_');
  const envKey = `APP_${normalizedName}_EMAIL`;
  return env[envKey];
}

/**
 * Try to infer app name from a CSP document URI.
 *
 * Uses heuristics to map known domains and protocols to app names:
 * - `signic.email` hostnames map to `mail_box`
 * - `chrome-extension:` protocol maps to `mail_box_wallet`
 *
 * @param documentUri - The document-uri field from the CSP report.
 * @returns The inferred app name, or undefined if no match.
 */
function inferAppName(documentUri: string): string | undefined {
  try {
    const url = new URL(documentUri);
    if (url.hostname.includes('signic.email')) {
      return 'mail_box';
    }
    if (url.protocol === 'chrome-extension:') {
      return 'mail_box_wallet';
    }
  } catch {
    // Invalid URL
  }
  return undefined;
}

/**
 * Extract hostname from a URL string.
 *
 * Falls back to returning the original string if URL parsing fails.
 *
 * @param urlString - The URL to extract the hostname from.
 * @returns The hostname portion of the URL, or the original string on failure.
 */
function extractHostname(urlString: string): string {
  try {
    const url = new URL(urlString);
    return url.hostname;
  } catch {
    return urlString;
  }
}

/**
 * Send an HTML email via the SendGrid v3 API.
 *
 * @param env - Environment bindings containing SENDGRID_API_KEY and FROM_EMAIL.
 * @param options - Email options including recipient, subject, and HTML body.
 * @returns True if the email was sent successfully, false otherwise.
 */
async function sendEmail(
  env: Env,
  options: { to: string; subject: string; html: string },
): Promise<boolean> {
  if (!env.SENDGRID_API_KEY) {
    console.error('SENDGRID_API_KEY not configured');
    return false;
  }

  const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.SENDGRID_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: options.to }] }],
      from: { email: env.FROM_EMAIL, name: 'Security Guard' },
      subject: options.subject,
      content: [{ type: 'text/html', value: options.html }],
    }),
  });

  if (!response.ok) {
    console.error('SendGrid error:', response.status, await response.text());
    return false;
  }

  return true;
}
