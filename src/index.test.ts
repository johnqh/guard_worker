import { describe, it, expect, vi, beforeEach } from 'vitest';

// Import the worker module
import worker from './index';

// Mock environment
const createMockEnv = (overrides = {}) => ({
  SENDGRID_API_KEY: 'test-api-key',
  FROM_EMAIL: 'security@test.com',
  APP_MAIL_BOX_EMAIL: 'mailbox@test.com',
  APP_MAIL_BOX_WALLET_EMAIL: 'wallet@test.com',
  ...overrides,
});

// Helper to create mock requests
const createMockRequest = (
  method: string,
  path: string,
  body?: unknown
): Request => {
  const url = `https://guard.example.com${path}`;
  const options: RequestInit = { method };
  if (body) {
    options.body = JSON.stringify(body);
    options.headers = { 'Content-Type': 'application/json' };
  }
  return new Request(url, options);
};

describe('Security Guard Worker', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    // Mock global fetch for SendGrid calls
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 202,
      text: () => Promise.resolve(''),
    });
  });

  describe('CORS handling', () => {
    it('should handle OPTIONS preflight requests', async () => {
      const request = createMockRequest('OPTIONS', '/alert');
      const response = await worker.fetch(request, createMockEnv());

      expect(response.status).toBe(200);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
      expect(response.headers.get('Access-Control-Allow-Methods')).toContain('POST');
    });

    it('should reject non-POST methods', async () => {
      const request = createMockRequest('GET', '/alert');
      const response = await worker.fetch(request, createMockEnv());

      expect(response.status).toBe(405);
    });
  });

  describe('Security Alert endpoint', () => {
    it('should handle valid security alerts', async () => {
      const alert = {
        appName: 'mail_box',
        type: 'unauthorized_fetch',
        url: 'https://malicious.com/api',
        hostname: 'malicious.com',
        timestamp: Date.now(),
      };

      const request = createMockRequest('POST', '/alert', alert);
      const response = await worker.fetch(request, createMockEnv());
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.success).toBe(true);
    });

    it('should reject alerts without appName', async () => {
      const alert = {
        type: 'unauthorized_fetch',
        url: 'https://malicious.com/api',
        hostname: 'malicious.com',
        timestamp: Date.now(),
      };

      const request = createMockRequest('POST', '/alert', alert);
      const response = await worker.fetch(request, createMockEnv());
      const data = await response.json();

      expect(response.status).toBe(400);
      expect(data.error).toBe('Missing appName');
    });

    it('should reject alerts for unknown apps', async () => {
      const alert = {
        appName: 'unknown_app',
        type: 'unauthorized_fetch',
        url: 'https://malicious.com/api',
        hostname: 'malicious.com',
        timestamp: Date.now(),
      };

      const request = createMockRequest('POST', '/alert', alert);
      const response = await worker.fetch(request, createMockEnv());
      const data = await response.json();

      expect(response.status).toBe(400);
      expect(data.error).toBe('Unknown app');
    });

    it('should accept alerts on /security-alert path', async () => {
      const alert = {
        appName: 'mail_box',
        type: 'unauthorized_xhr',
        url: 'https://malicious.com/data',
        hostname: 'malicious.com',
        timestamp: Date.now(),
      };

      const request = createMockRequest('POST', '/security-alert', alert);
      const response = await worker.fetch(request, createMockEnv());
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.success).toBe(true);
    });
  });

  describe('CSP Report endpoint', () => {
    it('should handle valid CSP reports with appName query param', async () => {
      const report = {
        'csp-report': {
          'document-uri': 'https://app.signic.email/page',
          'violated-directive': 'script-src',
          'blocked-uri': 'https://evil.com/script.js',
        },
      };

      const request = createMockRequest('POST', '/csp-report?appName=mail_box', report);
      const response = await worker.fetch(request, createMockEnv());

      expect(response.status).toBe(204);
    });

    it('should infer mail_box from signic.email domain', async () => {
      const report = {
        'csp-report': {
          'document-uri': 'https://app.signic.email/inbox',
          'violated-directive': 'img-src',
          'blocked-uri': 'https://tracker.com/pixel.gif',
        },
      };

      const request = createMockRequest('POST', '/csp-report', report);
      const response = await worker.fetch(request, createMockEnv());

      expect(response.status).toBe(204);
      expect(global.fetch).toHaveBeenCalled(); // Email was sent
    });

    it('should infer mail_box_wallet from chrome-extension protocol', async () => {
      const report = {
        'csp-report': {
          'document-uri': 'chrome-extension://abcd1234/popup.html',
          'violated-directive': 'connect-src',
          'blocked-uri': 'https://phishing.com/api',
        },
      };

      const request = createMockRequest('POST', '/csp-report', report);
      const response = await worker.fetch(request, createMockEnv());

      expect(response.status).toBe(204);
    });

    it('should return 204 for CSP reports without identifiable app', async () => {
      const report = {
        'csp-report': {
          'document-uri': 'https://unknown.com/page',
          'violated-directive': 'script-src',
          'blocked-uri': 'https://cdn.com/lib.js',
        },
      };

      const request = createMockRequest('POST', '/csp-report', report);
      const response = await worker.fetch(request, createMockEnv());

      expect(response.status).toBe(204);
    });
  });

  describe('Routing', () => {
    it('should return 404 for unknown paths', async () => {
      const request = createMockRequest('POST', '/unknown', { data: 'test' });
      const response = await worker.fetch(request, createMockEnv());

      expect(response.status).toBe(404);
    });
  });

  describe('Error handling', () => {
    it('should handle invalid JSON gracefully', async () => {
      const request = new Request('https://guard.example.com/alert', {
        method: 'POST',
        body: 'invalid json{',
        headers: { 'Content-Type': 'application/json' },
      });

      const response = await worker.fetch(request, createMockEnv());

      expect(response.status).toBe(500);
      const data = await response.json();
      expect(data.success).toBe(false);
    });

    it('should handle SendGrid failures', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve('SendGrid error'),
      });

      const alert = {
        appName: 'mail_box',
        type: 'unauthorized_fetch',
        url: 'https://malicious.com/api',
        hostname: 'malicious.com',
        timestamp: Date.now(),
      };

      const request = createMockRequest('POST', '/alert', alert);
      const response = await worker.fetch(request, createMockEnv());
      const data = await response.json();

      expect(response.status).toBe(500);
      expect(data.success).toBe(false);
    });

    it('should handle missing SendGrid API key', async () => {
      const alert = {
        appName: 'mail_box',
        type: 'unauthorized_fetch',
        url: 'https://malicious.com/api',
        hostname: 'malicious.com',
        timestamp: Date.now(),
      };

      const request = createMockRequest('POST', '/alert', alert);
      const env = createMockEnv({ SENDGRID_API_KEY: '' });
      const response = await worker.fetch(request, env);
      const data = await response.json();

      expect(response.status).toBe(500);
      expect(data.success).toBe(false);
    });
  });

  describe('App name normalization', () => {
    it('should normalize hyphenated app names', async () => {
      const alert = {
        appName: 'mail-box-wallet',
        type: 'unauthorized_fetch',
        url: 'https://malicious.com/api',
        hostname: 'malicious.com',
        timestamp: Date.now(),
      };

      const request = createMockRequest('POST', '/alert', alert);
      const response = await worker.fetch(request, createMockEnv());
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.success).toBe(true);
    });

    it('should handle mixed case app names', async () => {
      const alert = {
        appName: 'Mail_Box',
        type: 'unauthorized_fetch',
        url: 'https://malicious.com/api',
        hostname: 'malicious.com',
        timestamp: Date.now(),
      };

      const request = createMockRequest('POST', '/alert', alert);
      const response = await worker.fetch(request, createMockEnv());
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.success).toBe(true);
    });
  });
});
