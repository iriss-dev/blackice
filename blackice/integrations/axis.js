/**
 * blackice client for Axis Discord Bot & Node.js services.
 * Connects to local blackice daemon on 127.0.0.1:8787 for <0.1ms threat intelligence.
 * Safe fallback: never throws or blocks if daemon is temporarily offline.
 *
 * (C) 2026 Iris (iriss-dev) - GPL-3.0-or-later
 */

class BlackIceClient {
  constructor(options = {}) {
    this.baseUrl = options.url || process.env.BLACKICE_URL || 'http://127.0.0.1:8787';
    this.timeoutMs = options.timeoutMs || 800;
  }

  async check(ip) {
    if (!ip || typeof ip !== 'string') {
      return { isThreat: false, threatScore: 0, classification: 'INVALID', action: 'PASS' };
    }

    const cleanIp = ip.trim().replace(/^::ffff:/, ''); // Strip IPv4-mapped IPv6 prefix
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await fetch(`${this.baseUrl}/v1/intel/${encodeURIComponent(cleanIp)}`, {
        signal: controller.signal,
        headers: { 'User-Agent': 'Axis-SecurityBot/2.8' },
      });

      if (!res.ok) {
        return { isThreat: false, threatScore: 0, classification: 'ERROR', action: 'PASS', status: res.status };
      }

      const data = await res.json();
      return {
        ip: data.ip,
        isThreat: data.threat_score >= 75,
        threatScore: data.threat_score,
        classification: data.classification,
        action: data.action,
        confidence: data.confidence,
        matchedFeeds: data.matched_feeds || [],
        isTor: data.classification === 'TOR_EXIT' || (data.matched_feeds || []).includes('tor_exits'),
        isBotnet: data.classification === 'BOTNET_C2' || (data.matched_feeds || []).includes('feodo_tracker'),
      };
    } catch (err) {
      // Graceful offline fallback
      return {
        ip: cleanIp,
        isThreat: false,
        threatScore: 0,
        classification: 'OFFLINE_PASS',
        action: 'PASS',
        daemonOffline: true,
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  async ban(ip, reason = 'Axis bot quarantine', ttlSeconds = 86400) {
    try {
      const res = await fetch(`${this.baseUrl}/v1/firewall/ban`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason, ttl_seconds: ttlSeconds }),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  async unban(ip) {
    try {
      const res = await fetch(`${this.baseUrl}/v1/firewall/unban`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });
      return res.ok;
    } catch {
      return false;
    }
  }
}

module.exports = { BlackIceClient };
