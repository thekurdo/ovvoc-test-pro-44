const mongoose = require('mongoose');

const tokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  token: {
    type: String,
    required: true,
    unique: true
  },
  type: {
    type: String,
    enum: ['refresh', 'reset', 'verify'],
    default: 'refresh'
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expires: 0 }
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Invalidate token — uses deprecated remove() (replaced by deleteOne() in mongoose 7)
tokenSchema.methods.invalidate = function(callback) {
  return this.remove(callback);
};

// Invalidate all tokens for a user — callback-based
tokenSchema.statics.invalidateAllForUser = function(userId, callback) {
  return this.remove({ userId: userId }, callback);
};

// Find valid token — callback-based findOne
tokenSchema.statics.findValidToken = function(tokenString, callback) {
  return this.findOne({
    token: tokenString,
    expiresAt: { $gt: new Date() }
  }, callback);
};

// Clean expired tokens — uses deprecated update() 
tokenSchema.statics.cleanExpired = function(callback) {
  return this.remove(
    { expiresAt: { $lt: new Date() } },
    callback
  );
};

const Token = mongoose.model('Token', tokenSchema);

module.exports = Token;
