/**
 * @fileoverview Email formatting utilities for security alert notifications.
 *
 * Contains the HTML email template generator and HTML escaping function.
 * All user-supplied strings are escaped to prevent XSS in email clients.
 */

/** Security alert payload sent by client-side interceptors. */
export interface SecurityAlert {
  /** Name of the application that generated the alert. */
  appName: string;
  /** Type of security violation detected. */
  type:
    | 'unauthorized_fetch'
    | 'unauthorized_xhr'
    | 'unauthorized_websocket'
    | 'csp_violation';
  /** The URL that was blocked or flagged. */
  url: string;
  /** Hostname extracted from the blocked URL. */
  hostname: string;
  /** Unix timestamp (ms) when the alert was generated. */
  timestamp: number;
  /** Optional stack trace from the interceptor. */
  stack?: string;
  /** Optional application version string. */
  appVersion?: string;
  /** Optional user agent string from the browser. */
  userAgent?: string;
  /** Optional additional context as key-value pairs. */
  metadata?: Record<string, unknown>;
}

/** Valid alert type values for runtime validation. */
export const VALID_ALERT_TYPES: readonly SecurityAlert['type'][] = [
  'unauthorized_fetch',
  'unauthorized_xhr',
  'unauthorized_websocket',
  'csp_violation',
] as const;

/**
 * Format a security alert as a styled HTML email.
 *
 * Generates a full HTML document with inline CSS containing alert details.
 * All user-supplied values are passed through `escapeHtml()` to prevent XSS.
 *
 * @param alert - The security alert data to format.
 * @returns Complete HTML document string ready for email delivery.
 */
export function formatSecurityAlertEmail(alert: SecurityAlert): string {
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
      ${
        alert.appVersion
          ? `
      <div class="field">
        <div class="label">App Version</div>
        <div class="value">${escapeHtml(alert.appVersion)}</div>
      </div>
      `
          : ''
      }
      ${
        alert.userAgent
          ? `
      <div class="field">
        <div class="label">User Agent</div>
        <div class="value">${escapeHtml(alert.userAgent)}</div>
      </div>
      `
          : ''
      }
      ${
        alert.stack
          ? `
      <div class="field">
        <div class="label">Stack Trace</div>
        <div class="value stack">${escapeHtml(alert.stack)}</div>
      </div>
      `
          : ''
      }
      ${
        alert.metadata
          ? `
      <div class="field">
        <div class="label">Additional Details</div>
        <div class="value"><pre>${escapeHtml(JSON.stringify(alert.metadata, null, 2))}</pre></div>
      </div>
      `
          : ''
      }
    </div>
  </div>
</body>
</html>
  `.trim();
}

/**
 * Escape HTML special characters to prevent XSS in email templates.
 *
 * Replaces `&`, `<`, `>`, `"`, and `'` with their HTML entity equivalents.
 *
 * @param str - The raw string to escape.
 * @returns The HTML-safe escaped string.
 */
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
