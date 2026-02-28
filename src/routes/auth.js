const express = require('express');
const router = express.Router();
const passport = require('passport');
const User = require('../models/User');
const Token = require('../models/Token');
const { generateTokenPair, verifyToken, signAccessToken } = require('../auth/jwt');
const { requireAuth, rateLimit } = require('../middleware/auth');

// POST /auth/register — create new user
router.post('/register', rateLimit(5, 60000), async function(req, res) {
  try {
    const { email, password, name } = req.body;

    // Check if user exists — callback-based findOne (mongoose 6)
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const user = await User.create({ email, password, name });
    const tokens = generateTokenPair(user);

    // Store refresh token
    await Token.create({
      userId: user._id,
      token: tokens.refreshToken,
      type: 'refresh',
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    res.status(201).json({
      message: 'Registration successful',
      user: { id: user._id, email: user.email, name: user.name },
      ...tokens
    });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed', details: err.message });
  }
});

// POST /auth/login — authenticate and return JWT
router.post('/login', rateLimit(10, 60000), function(req, res, next) {
  passport.authenticate('local', { session: false }, async function(err, user, info) {
    if (err) return next(err);
    if (!user) {
      return res.status(401).json({ error: info.message || 'Authentication failed' });
    }

    try {
      const tokens = generateTokenPair(user);

      // Store refresh token
      await Token.create({
        userId: user._id,
        token: tokens.refreshToken,
        type: 'refresh',
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      });

      // Update last login — callback-based update (mongoose 6)
      user.update({ lastLogin: new Date() }, function() {});

      res.json({
        message: 'Login successful',
        user: { id: user._id, email: user.email, name: user.name, role: user.role },
        ...tokens
      });
    } catch (err) {
      next(err);
    }
  })(req, res, next);
});

// POST /auth/logout — invalidate tokens
// passport 0.6: req.logout() without callback (passport 0.7+ requires callback)
router.post('/logout', requireAuth, async function(req, res) {
  try {
    const refreshToken = req.body.refreshToken;
    if (refreshToken) {
      // Invalidate refresh token — uses remove() (mongoose 6)
      const token = await Token.findOne({ token: refreshToken });
      if (token) {
        token.remove();
      }
    }

    // Passport 0.6 logout — no callback required
    req.logout();

    res.json({ message: 'Logout successful' });
  } catch (err) {
    res.status(500).json({ error: 'Logout failed' });
  }
});

// POST /auth/refresh — refresh access token
router.post('/refresh', rateLimit(20, 60000), async function(req, res) {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token required' });
    }

    // Verify refresh token
    const decoded = verifyToken(refreshToken);
    if (!decoded || decoded.type !== 'refresh') {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    // Check token exists in DB — callback-based findOne (mongoose 6)
    const storedToken = await Token.findOne({
      token: refreshToken,
      expiresAt: { $gt: new Date() }
    });

    if (!storedToken) {
      return res.status(401).json({ error: 'Refresh token expired or revoked' });
    }

    // Find user
    const user = await User.findById(decoded.userId);
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'User not found or inactive' });
    }

    // Generate new access token
    const newAccessToken = signAccessToken({
      userId: user._id,
      email: user.email,
      role: user.role
    });

    res.json({
      accessToken: newAccessToken,
      expiresIn: '15m'
    });
  } catch (err) {
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

// GET /auth/me — get current user
router.get('/me', requireAuth, async function(req, res) {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user: user });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// DELETE /auth/account — delete user account
// Uses deprecated remove() method (mongoose 6)
router.delete('/account', requireAuth, async function(req, res) {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Invalidate all tokens — uses remove() (mongoose 6)
    await Token.remove({ userId: user._id });

    // Delete user — uses deprecated remove() (mongoose 6)
    await user.remove();

    res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Account deletion failed' });
  }
});

// Express 4 wildcard — must become /{*path} in Express 5
router.get('/{*path}', function(req, res) {
  res.status(404).json({ error: 'Auth route not found' });
});

module.exports = router;
