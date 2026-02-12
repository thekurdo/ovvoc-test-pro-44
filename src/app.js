const express = require('express');
const cors = require('cors');
const session = require('express-session');
const passport = require('./auth/passport');
const authRoutes = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 3044;

// Middleware
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));

// Session config (for passport)
app.use(session({
  secret: process.env.SESSION_SECRET || 'ovvoc-test-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Health check
app.get('/health', function(req, res) {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Auth routes
app.use('/auth', authRoutes);

// Express 4 wildcard catch-all — must become /{*path} in Express 5
app.get('*', function(req, res) {
  res.status(404).json({ error: 'Route not found' });
});

// Error handler
app.use(function(err, req, res, next) {
  console.error('Unhandled error:', err.message);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start server only if run directly
if (require.main === module) {
  app.listen(PORT, function() {
    console.log('Auth server running on port ' + PORT);
  });
}

module.exports = app;
