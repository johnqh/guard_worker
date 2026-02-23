import { describe, it, expect } from 'vitest';
import {
  formatSecurityAlertEmail,
  escapeHtml,
  type SecurityAlert,
} from './email';

describe('escapeHtml', () => {
  it('should escape ampersands', () => {
    expect(escapeHtml('foo & bar')).toBe('foo &amp; bar');
  });

  it('should escape angle brackets', () => {
    expect(escapeHtml('<script>alert("xss")</script>')).toBe(
      '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;',
    );
  });

  it('should escape single quotes', () => {
    expect(escapeHtml("it's")).toBe('it&#039;s');
  });

  it('should handle strings with no special characters', () => {
    expect(escapeHtml('hello world')).toBe('hello world');
  });

  it('should handle empty strings', () => {
    expect(escapeHtml('')).toBe('');
  });
});

describe('formatSecurityAlertEmail', () => {
  const baseAlert: SecurityAlert = {
    appName: 'mail_box',
    type: 'unauthorized_fetch',
    url: 'https://malicious.com/api',
    hostname: 'malicious.com',
    timestamp: 1700000000000,
  };

  it('should include required fields in the email', () => {
    const html = formatSecurityAlertEmail(baseAlert);

    expect(html).toContain('Security Alert');
    expect(html).toContain('UNAUTHORIZED FETCH');
    expect(html).toContain('mail_box');
    expect(html).toContain('malicious.com');
    expect(html).toContain('https://malicious.com/api');
  });

  it('should include appVersion when present', () => {
    const alert: SecurityAlert = { ...baseAlert, appVersion: '1.2.3' };
    const html = formatSecurityAlertEmail(alert);

    expect(html).toContain('App Version');
    expect(html).toContain('1.2.3');
  });

  it('should not include appVersion when absent', () => {
    const html = formatSecurityAlertEmail(baseAlert);

    expect(html).not.toContain('App Version');
  });

  it('should include userAgent when present', () => {
    const alert: SecurityAlert = {
      ...baseAlert,
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    };
    const html = formatSecurityAlertEmail(alert);

    expect(html).toContain('User Agent');
    expect(html).toContain('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)');
  });

  it('should not include userAgent when absent', () => {
    const html = formatSecurityAlertEmail(baseAlert);

    expect(html).not.toContain('User Agent');
  });

  it('should include stack trace when present', () => {
    const alert: SecurityAlert = {
      ...baseAlert,
      stack: 'Error: blocked\n  at fetch (main.js:10)',
    };
    const html = formatSecurityAlertEmail(alert);

    expect(html).toContain('Stack Trace');
    expect(html).toContain('Error: blocked');
  });

  it('should include metadata when present', () => {
    const alert: SecurityAlert = {
      ...baseAlert,
      metadata: { documentUri: 'https://example.com/page' },
    };
    const html = formatSecurityAlertEmail(alert);

    expect(html).toContain('Additional Details');
    expect(html).toContain('documentUri');
  });

  it('should escape HTML in user-supplied fields', () => {
    const alert: SecurityAlert = {
      ...baseAlert,
      appName: '<script>xss</script>',
      url: 'https://example.com?q=<b>bold</b>',
      hostname: '<img onerror=alert(1)>',
    };
    const html = formatSecurityAlertEmail(alert);

    expect(html).toContain('&lt;script&gt;xss&lt;/script&gt;');
    expect(html).toContain('&lt;b&gt;bold&lt;/b&gt;');
    expect(html).toContain('&lt;img onerror=alert(1)&gt;');
    expect(html).not.toContain('<script>xss</script>');
  });

  it('should escape HTML in optional user-supplied fields', () => {
    const alert: SecurityAlert = {
      ...baseAlert,
      appVersion: '<b>1.0</b>',
      userAgent: '<script>evil()</script>',
      stack: '<img src=x onerror=alert(1)>',
    };
    const html = formatSecurityAlertEmail(alert);

    expect(html).toContain('&lt;b&gt;1.0&lt;/b&gt;');
    expect(html).toContain('&lt;script&gt;evil()&lt;/script&gt;');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('should produce valid HTML structure', () => {
    const html = formatSecurityAlertEmail(baseAlert);

    expect(html).toMatch(/^<!DOCTYPE html>/);
    expect(html).toContain('</html>');
    expect(html).toContain('<head>');
    expect(html).toContain('</head>');
    expect(html).toContain('<body>');
    expect(html).toContain('</body>');
  });
});
