const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Remove user — uses deprecated remove() (gone in mongoose 7, replaced by deleteOne())
userSchema.methods.removeAccount = function(callback) {
  return this.remove(callback);
};

// Update user with callback — deprecated in mongoose 7
userSchema.methods.updateProfile = function(updates, callback) {
  return this.update(updates, callback);
};

// Find user by email — callback-based findOne (deprecated in mongoose 7)
userSchema.statics.findByEmail = function(email, callback) {
  return this.findOne({ email: email }, callback);
};

// Find active users — callback-based find
userSchema.statics.findActiveUsers = function(callback) {
  return this.find({ isActive: true }, callback);
};

// Deactivate user — callback-based update
userSchema.statics.deactivateUser = function(userId, callback) {
  return this.update(
    { _id: userId },
    { $set: { isActive: false } },
    callback
  );
};

const User = mongoose.model('User', userSchema);

module.exports = User;
