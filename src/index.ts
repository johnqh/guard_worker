/**
 * Security Guard Worker
 *
 * Receives security alerts and CSP violation reports,
 * sends email notifications via SendGrid.
 *
 * App registry: Configure recipient emails in wrangler.toml
 * as APP_<APPNAME>_EMAIL environment variables.
 */

interface Env {
  SENDGRID_API_KEY: string;
  FROM_EMAIL: string;
  [key: string]: string; // App registry: APP_<APPNAME>_EMAIL
}

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

// CORS headers for cross-origin requests
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export default {
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
        }
      );
    }
  },
};

/**
 * Handle security alerts from client-side interceptors
 */
async function handleSecurityAlert(request: Request, env: Env): Promise<Response> {
  const alert: SecurityAlert = await request.json();

  if (!alert.appName) {
    return new Response(
      JSON.stringify({ success: false, error: 'Missing appName' }),
      {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  }

  const recipient = getRecipientEmail(alert.appName, env);
  if (!recipient) {
    console.warn(`Unknown app: ${alert.appName}`);
    return new Response(
      JSON.stringify({ success: false, error: 'Unknown app' }),
      {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      }
    );
  }

  const emailSent = await sendEmail(env, {
    to: recipient,
    subject: `[Security Alert] ${alert.appName}: ${alert.type}`,
    html: formatSecurityAlertEmail(alert),
  });

  return new Response(
    JSON.stringify({ success: emailSent }),
    {
      status: emailSent ? 200 : 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    }
  );
}

/**
 * Handle CSP violation reports from browser
 */
async function handleCspReport(request: Request, env: Env, url: URL): Promise<Response> {
  const report: CspReport = await request.json();
  const cspData = report['csp-report'];

  // Get appName from query param or try to infer from document-uri
  const appName = url.searchParams.get('appName') || inferAppName(cspData['document-uri']);

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
 * Get recipient email from app registry
 */
function getRecipientEmail(appName: string, env: Env): string | undefined {
  // Normalize app name: mail_box_wallet -> MAIL_BOX_WALLET
  const normalizedName = appName.toUpperCase().replace(/-/g, '_');
  const envKey = `APP_${normalizedName}_EMAIL`;
  return env[envKey];
}

/**
 * Try to infer app name from document URI
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
 * Extract hostname from URL
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
 * Send email via SendGrid API
 */
async function sendEmail(
  env: Env,
  options: { to: string; subject: string; html: string }
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

/**
 * Format security alert as HTML email
 */
function formatSecurityAlertEmail(alert: SecurityAlert): string {
  const timestamp = new Date(alert.timestamp).toISOString();

  return `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #dc2626; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
    .content { background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px; }
    .field { margin-bottom: 12px; }
    .label { font-weight: 600; color: #6b7280; font-size: 12px; text-transform: uppercase; }
    .value { font-family: monospace; background: #e5e7eb; padding: 8px 12px; border-radius: 4px; word-break: break-all; }
    .stack { font-size: 12px; white-space: pre-wrap; max-height: 200px; overflow: auto; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h2 style="margin: 0;">Security Alert</h2>
      <p style="margin: 8px 0 0 0; opacity: 0.9;">${alert.type.replace(/_/g, ' ').toUpperCase()}</p>
    </div>
    <div class="content">
      <div class="field">
        <div class="label">Application</div>
        <div class="value">${escapeHtml(alert.appName)}</div>
      </div>
      <div class="field">
        <div class="label">Date & Time</div>
        <div class="value">${timestamp}</div>
      </div>
      <div class="field">
        <div class="label">Blocked URL</div>
        <div class="value">${escapeHtml(alert.url)}</div>
      </div>
      <div class="field">
        <div class="label">Hostname</div>
        <div class="value">${escapeHtml(alert.hostname)}</div>
      </div>
      ${alert.appVersion ? `
      <div class="field">
        <div class="label">App Version</div>
        <div class="value">${escapeHtml(alert.appVersion)}</div>
      </div>
      ` : ''}
      ${alert.stack ? `
      <div class="field">
        <div class="label">Stack Trace</div>
        <div class="value stack">${escapeHtml(alert.stack)}</div>
      </div>
      ` : ''}
      ${alert.metadata ? `
      <div class="field">
        <div class="label">Additional Details</div>
        <div class="value"><pre>${escapeHtml(JSON.stringify(alert.metadata, null, 2))}</pre></div>
      </div>
      ` : ''}
    </div>
  </div>
</body>
</html>
  `.trim();
}

/**
 * Escape HTML special characters
 */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
