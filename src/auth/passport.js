const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../models/User');

// Configure Local Strategy with callback-based findOne (mongoose 6 pattern)
passport.use(new LocalStrategy(
  {
    usernameField: 'email',
    passwordField: 'password'
  },
  function(email, password, done) {
    // Callback-based findOne — deprecated in mongoose 7
    User.findOne({ email: email.toLowerCase() }, function(err, user) {
      if (err) return done(err);
      if (!user) {
        return done(null, false, { message: 'Invalid email or password' });
      }
      user.comparePassword(password)
        .then(function(isMatch) {
          if (!isMatch) {
            return done(null, false, { message: 'Invalid email or password' });
          }
          return done(null, user);
        })
        .catch(function(err) {
          return done(err);
        });
    });
  }
));

// Serialize user — stores user ID in session
passport.serializeUser(function(user, done) {
  done(null, user._id);
});

// Deserialize user — callback-based findById (mongoose 6 pattern)
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

module.exports = passport;
