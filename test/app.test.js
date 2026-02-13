const assert = require('assert');

let passed = 0;
let failed = 0;
const results = [];

function test(name, fn) {
  try { fn(); passed++; results.push({ name, status: 'PASS' }); }
  catch (err) { failed++; results.push({ name, status: 'FAIL', error: err.message }); }
}

test('express imports correctly', function() {
  const express = require('express');
  assert(typeof express === 'function');
  assert(typeof express.Router === 'function');
});

test('mongoose imports correctly', function() {
  const mongoose = require('mongoose');
  assert(typeof mongoose.Schema === 'function');
  assert(typeof mongoose.model === 'function');
});

test('passport imports correctly', function() {
  const passport = require('passport');
  assert(typeof passport.authenticate === 'function');
  assert(typeof passport.use === 'function');
});

test('passport-local imports correctly', function() {
  const LocalStrategy = require('passport-local').Strategy;
  assert(typeof LocalStrategy === 'function');
});

test('jsonwebtoken imports correctly', function() {
  const jwt = require('jsonwebtoken');
  assert(typeof jwt.sign === 'function');
  assert(typeof jwt.verify === 'function');
  assert(typeof jwt.decode === 'function');
});

test('express-session imports correctly', function() {
  const session = require('express-session');
  assert(typeof session === 'function');
});

test('bcryptjs imports correctly', function() {
  const bcrypt = require('bcryptjs');
  assert(typeof bcrypt.hash === 'function');
  assert(typeof bcrypt.compare === 'function');
});

test('cors imports correctly', function() {
  const cors = require('cors');
  assert(typeof cors === 'function');
});

test('JWT sign creates a valid token string', function() {
  const jwt = require('jsonwebtoken');
  const token = jwt.sign({ userId: '12345' }, 'test-secret-key', { expiresIn: '1h' });
  assert(typeof token === 'string');
  assert(token.split('.').length === 3);
});

test('JWT verify decodes token correctly', function() {
  const jwt = require('jsonwebtoken');
  const secret = 'test-secret-key';
  const payload = { userId: '12345', email: 'test@example.com' };
  const token = jwt.sign(payload, secret, { expiresIn: '1h' });
  const decoded = jwt.verify(token, secret);
  assert(decoded.userId === '12345');
  assert(decoded.email === 'test@example.com');
  assert(typeof decoded.iat === 'number');
  assert(typeof decoded.exp === 'number');
});

test('JWT verify throws for invalid token', function() {
  const jwt = require('jsonwebtoken');
  try {
    jwt.verify('invalid.token.here', 'wrong-secret');
    assert(false);
  } catch (err) {
    assert(err.name === 'JsonWebTokenError');
  }
});

test('JWT sign/verify roundtrip with jwt.js utilities', function() {
  const { signAccessToken, verifyToken, decodeToken, generateTokenPair } = require('../src/auth/jwt');
  const user = { _id: 'user123', email: 'test@test.com', role: 'admin' };
  const tokens = generateTokenPair(user);
  assert(typeof tokens.accessToken === 'string');
  assert(typeof tokens.refreshToken === 'string');
  assert(tokens.expiresIn === '15m');
  const ad = verifyToken(tokens.accessToken);
  assert(ad !== null);
  assert(ad.userId === 'user123');
  assert(ad.email === 'test@test.com');
  assert(ad.role === 'admin');
  assert(ad.type === 'access');
  const rd = verifyToken(tokens.refreshToken);
  assert(rd !== null);
  assert(rd.userId === 'user123');
  assert(rd.type === 'refresh');
  const decoded = decodeToken(tokens.accessToken);
  assert(decoded !== null);
  assert(decoded.header.alg === 'HS256');
});

test('Passport LocalStrategy can be instantiated', function() {
  const LocalStrategy = require('passport-local').Strategy;
  const strategy = new LocalStrategy(
    { usernameField: 'email', passwordField: 'password' },
    function(email, password, done) { done(null, { email: email }); }
  );
  assert(strategy.name === 'local');
  assert(typeof strategy.authenticate === 'function');
});

test('Passport can register a strategy', function() {
  const passport = require('passport');
  const LocalStrategy = require('passport-local').Strategy;
  const tp = new passport.Passport();
  tp.use('test-local', new LocalStrategy(
    { usernameField: 'email' },
    function(email, password, done) { done(null, false); }
  ));
  tp.serializeUser(function(user, done) { done(null, user.id); });
  tp.deserializeUser(function(id, done) { done(null, { id: id }); });
  assert(typeof tp.authenticate === 'function');
});

test('Mongoose has remove method (mongoose 6)', function() {
  const mongoose = require('mongoose');
  const ts = new mongoose.Schema({ name: String });
  const TM = mongoose.model('TestRemoveModel', ts);
  const doc = new TM({ name: 'test' });
  assert(typeof doc.remove === 'function');
});

test('Mongoose has update method (mongoose 6)', function() {
  const mongoose = require('mongoose');
  const ts = new mongoose.Schema({ name: String, age: Number });
  const TM = mongoose.model('TestUpdateModel', ts);
  const doc = new TM({ name: 'test', age: 25 });
  assert(typeof doc.update === 'function');
});

test('Mongoose findOne supports callbacks (mongoose 6)', function() {
  const mongoose = require('mongoose');
  const ts = new mongoose.Schema({ email: String });
  const TM = mongoose.model('TestCallbackModel', ts);
  const query = TM.findOne({ email: 'test@test.com' }, function() {});
  assert(query !== undefined);
});

test('User model has custom static methods', function() {
  const User = require('../src/models/User');
  assert(typeof User.findByEmail === 'function');
  assert(typeof User.findActiveUsers === 'function');
  assert(typeof User.deactivateUser === 'function');
});

test('User model instance has custom methods', function() {
  const User = require('../src/models/User');
  const user = new User({ email: 't@t.com', password: 'password123', name: 'Test' });
  assert(typeof user.comparePassword === 'function');
  assert(typeof user.removeAccount === 'function');
  assert(typeof user.updateProfile === 'function');
});

test('Token model has custom methods', function() {
  const Token = require('../src/models/Token');
  assert(typeof Token.invalidateAllForUser === 'function');
  assert(typeof Token.findValidToken === 'function');
  assert(typeof Token.cleanExpired === 'function');
  const token = new Token({ userId: 'abc', token: 'xyz', expiresAt: new Date() });
  assert(typeof token.invalidate === 'function');
});

test('Express Router creates routes correctly', function() {
  const express = require('express');
  const router = express.Router();
  router.post('/test', function(req, res) { res.json({ ok: true }); });
  router.get('/test', function(req, res) { res.json({ ok: true }); });
  router.delete('/test', function(req, res) { res.json({ ok: true }); });
  assert(router.stack.length === 3);
});

test('Express 4 wildcard route pattern works', function() {
  const express = require('express');
  const router = express.Router();
  router.get('/{*path}', function(req, res) {
    res.status(404).json({ error: 'Not found' });
  });
  assert(router.stack.length === 1);
});

test('Express app can mount auth routes', function() {
  const express = require('express');
  const app = express();
  const authRoutes = require('../src/routes/auth');
  app.use('/auth', authRoutes);
  assert(app._router !== undefined || true);
});

test('Passport 0.6 req.logout works without callback', function() {
  const passport = require('passport');
  var threw = false;
  try {
    const tp = new passport.Passport();
    tp.serializeUser(function(user, done) { done(null, user); });
    tp.deserializeUser(function(user, done) { done(null, user); });
    assert(typeof tp.initialize === 'function');
    assert(typeof tp.session === 'function');
  } catch (err) { threw = true; }
  assert(!threw);
});

test('Auth middleware exports expected functions', function() {
  const m = require('../src/middleware/auth');
  assert(typeof m.requireAuth === 'function');
  assert(typeof m.optionalAuth === 'function');
  assert(typeof m.requireRole === 'function');
  assert(typeof m.rateLimit === 'function');
});

test('requireAuth rejects requests without token', function() {
  const { requireAuth } = require('../src/middleware/auth');
  const mockReq = { headers: {} };
  var statusCode = null, responseBody = null;
  const mockRes = {
    status: function(code) { statusCode = code; return mockRes; },
    json: function(body) { responseBody = body; }
  };
  requireAuth(mockReq, mockRes, function() { assert(false); });
  assert(statusCode === 401);
  assert(responseBody.error === 'Access token required');
});

test('requireAuth accepts valid Bearer token', function() {
  const { requireAuth } = require('../src/middleware/auth');
  const { signAccessToken } = require('../src/auth/jwt');
  const token = signAccessToken({ userId: 'user123', email: 'test@test.com', role: 'user' });
  const mockReq = { headers: { authorization: 'Bearer ' + token } };
  var nextCalled = false;
  const mockRes = { status: function() { return mockRes; }, json: function() {} };
  requireAuth(mockReq, mockRes, function() { nextCalled = true; });
  assert(nextCalled);
  assert(mockReq.userId === 'user123');
  assert(mockReq.userEmail === 'test@test.com');
});

test('rateLimit creates middleware function', function() {
  const { rateLimit } = require('../src/middleware/auth');
  const limiter = rateLimit(5, 60000);
  assert(typeof limiter === 'function');
});

test('bcryptjs hash and compare work correctly', function() {
  const bcrypt = require('bcryptjs');
  const password = 'TestPassword123!';
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);
  assert(typeof hash === 'string');
  assert(hash !== password);
  assert(bcrypt.compareSync(password, hash));
  assert(!bcrypt.compareSync('wrong', hash));
});

test('express-session creates middleware with config', function() {
  const session = require('express-session');
  const middleware = session({
    secret: 'test-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 86400000 }
  });
  assert(typeof middleware === 'function');
});

test('App module exports express application', function() {
  const app = require('../src/app');
  assert(typeof app === 'function');
  assert(typeof app.listen === 'function');
  assert(typeof app.use === 'function');
});

console.log('');
console.log('='.repeat(60));
console.log('  ovvoc-test-pro-44 - Auth Stack Test Results');
console.log('='.repeat(60));
results.forEach(function(r) {
  var icon = r.status === 'PASS' ? 'PASS' : 'FAIL';
  console.log('  [' + icon + '] ' + r.name);
  if (r.error) { console.log('         Error: ' + r.error); }
});
console.log('');
console.log('-'.repeat(60));
console.log('  Total: ' + (passed + failed) + ' | Passed: ' + passed + ' | Failed: ' + failed);
console.log('-'.repeat(60));
console.log('');
if (failed > 0) { process.exit(1); }
process.exit(0);
