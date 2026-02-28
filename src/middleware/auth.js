const { verifyToken } = require('../auth/jwt');

// JWT verification middleware
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access token required' });
  }

  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);

  if (!decoded) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  if (decoded.type !== 'access') {
    return res.status(401).json({ error: 'Invalid token type' });
  }

  req.userId = decoded.userId;
  req.userEmail = decoded.email;
  req.userRole = decoded.role;
  next();
}

// Optional auth — doesn't fail if no token present
function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    const decoded = verifyToken(token);
    if (decoded && decoded.type === 'access') {
      req.userId = decoded.userId;
      req.userEmail = decoded.email;
      req.userRole = decoded.role;
    }
  }

  next();
}

// Role-based authorization
function requireRole(role) {
  return function(req, res, next) {
    if (req.userRole !== role) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Simple rate limiter for auth routes
// Stores request counts in memory (per IP)
function rateLimit(maxRequests, windowMs) {
  const requests = new Map();

  // Cleanup old entries periodically
  setInterval(function() {
    const now = Date.now();
    for (const [key, value] of requests) {
      if (now - value.startTime > windowMs) {
        requests.delete(key);
      }
    }
  }, windowMs);

  return function(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const record = requests.get(ip);

    if (!record || now - record.startTime > windowMs) {
      requests.set(ip, { count: 1, startTime: now });
      return next();
    }

    if (record.count >= maxRequests) {
      return res.status(429).json({
        error: 'Too many requests',
        retryAfter: Math.ceil((record.startTime + windowMs - now) / 1000)
      });
    }

    record.count++;
    next();
  };
}

module.exports = {
  requireAuth,
  optionalAuth,
  requireRole,
  rateLimit
};
