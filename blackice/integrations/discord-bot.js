/**
 * BlackICE client for Discord bots (discord.js) & Node.js backend services.
 * Connects to local BlackICE daemon on 127.0.0.1:8787 for <0.1ms threat intelligence
 * and VirusTotal-style Multi-Engine Consensus scoring.
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
        headers: { 'User-Agent': 'blackice-node-client/1.0' },
      });

      if (!res.ok) {
        return { isThreat: false, threatScore: 0, classification: 'ERROR', action: 'PASS', status: res.status };
      }

      const data = await res.json();
      const consensus = data.consensus || {};

      return {
        ip: data.ip,
        isThreat: (data.threat_score >= 75) || (consensus.verdict === 'MALICIOUS'),
        threatScore: data.threat_score,
        classification: data.classification,
        action: data.action,
        confidence: data.confidence,
        ratio: consensus.ratio || '0/4',
        detectionRate: consensus.detection_rate || 0,
        consensus: consensus,
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

  /**
   * Evaluates text/message content for phishing URLs, high-entropy tokens, and exploit patterns.
   * Useful for Discord bot chat moderation & automod.
   */
  async inspectPayload(text) {
    if (!text || typeof text !== 'string') {
      return { isSuspicious: false, threatScore: 0, entropy: 0.0 };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await fetch(`${this.baseUrl}/v1/payload/inspect`, {
        method: 'POST',
        signal: controller.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: text }),
      });

      if (!res.ok) {
        return { isSuspicious: false, threatScore: 0, entropy: 0.0 };
      }

      const data = await res.json();
      return {
        isSuspicious: data.is_suspicious,
        threatScore: data.threat_score,
        entropy: data.shannon_entropy,
        patterns: data.suspicious_patterns || [],
      };
    } catch {
      return { isSuspicious: false, threatScore: 0, entropy: 0.0, daemonOffline: true };
    } finally {
      clearTimeout(timeout);
    }
  }

  async ban(ip, reason = 'Automated bot quarantine', ttlSeconds = 86400) {
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
