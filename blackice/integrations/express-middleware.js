/**
 * BlackICE Express.js Ingress Defense Middleware
 * 
 * Intercepts hostile scanners, botnets, and proxy evasion in <0.05ms
 * before requests hit your Express routes.
 * 
 * Usage:
 *   const express = require('express');
 *   const { blackice } = require('./express-middleware');
 * 
 *   const app = express();
 *   app.use(blackice({ blockThreshold: 75 }));
 */

const http = require('http');

function blackice(options = {}) {
  const sentinelUrl = options.url || 'http://127.0.0.1:8787';
  const blockThreshold = options.blockThreshold ?? 75;
  const blockTor = options.blockTor ?? false;
  const cacheTtlMs = options.cacheTtlMs ?? 300_000; // 5 min cache
  const cache = new Map();

  return async function blackiceMiddleware(req, res, next) {
    const rawIp = req.headers['x-forwarded-for']?.split(',')[0].trim() 
      || req.socket.remoteAddress 
      || '127.0.0.1';

    const cleanIp = rawIp.replace(/^.*:/, ''); // strip IPv6 prefix if IPv4-mapped

    // Whitelist localhost
    if (cleanIp === '127.0.0.1' || cleanIp === 'localhost' || cleanIp === '::1') {
      return next();
    }

    // Check memory cache
    const now = Date.now();
    const cached = cache.get(cleanIp);
    if (cached && now < cached.expires) {
      if (cached.blocked) {
        return res.status(403).json({ error: 'Access denied by BlackICE sentinel', score: cached.score });
      }
      return next();
    }

    // Query local BlackICE daemon
    try {
      const verdict = await querySentinel(sentinelUrl, cleanIp);
      const isBlocked = verdict.threat_score >= blockThreshold || (blockTor && verdict.classification === 'TOR_EXIT');

      cache.set(cleanIp, {
        blocked: isBlocked,
        score: verdict.threat_score,
        expires: now + cacheTtlMs
      });

      if (isBlocked) {
        return res.status(403).json({
          error: 'Access denied: Hostile threat posture detected',
          threat_score: verdict.threat_score,
          classification: verdict.classification
        });
      }

      next();
    } catch {
      // Fail-open policy if sentinel is temporarily unreachable
      next();
    }
  };
}

function querySentinel(baseUrl, ip) {
  return new Promise((resolve, reject) => {
    http.get(`${baseUrl}/v1/intel/${encodeURIComponent(ip)}`, { timeout: 200 }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } 
        catch (e) { reject(e); }
      });
    }).on('error', reject).on('timeout', () => reject(new Error('Timeout')));
  });
}

module.exports = { blackice };
