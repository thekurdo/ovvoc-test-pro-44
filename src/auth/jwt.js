const jwt = require('jsonwebtoken');

const JWT_SECRET = 'ovvoc-test-secret-key-do-not-use-in-production';
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';

// Sign access token — no algorithms option (required in jwt 9)
// jwt 9 requires explicit algorithm specification
function signAccessToken(payload) {
  return jwt.sign(
    {
      userId: payload.userId,
      email: payload.email,
      role: payload.role,
      type: 'access'
    },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );
}

// Sign refresh token — simple string secret (jwt 9 requires Buffer or KeyObject)
function signRefreshToken(payload) {
  return jwt.sign(
    {
      userId: payload.userId,
      type: 'refresh'
    },
    JWT_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRY }
  );
}

// Verify token — simple string secret (jwt 9 requires algorithms option + Buffer)
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
}

// Decode token without verification
function decodeToken(token) {
  return jwt.decode(token, { complete: true });
}

// Generate token pair
function generateTokenPair(user) {
  const payload = {
    userId: user._id || user.id,
    email: user.email,
    role: user.role || 'user'
  };

  return {
    accessToken: signAccessToken(payload),
    refreshToken: signRefreshToken(payload),
    expiresIn: ACCESS_TOKEN_EXPIRY
  };
}

module.exports = {
  JWT_SECRET,
  ACCESS_TOKEN_EXPIRY,
  REFRESH_TOKEN_EXPIRY,
  signAccessToken,
  signRefreshToken,
  verifyToken,
  decodeToken,
  generateTokenPair
};
