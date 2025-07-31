const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50,
    index: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    index: true
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  firstName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  role: {
    type: String,
    enum: ['admin', 'analyst', 'viewer', 'operator'],
    default: 'viewer',
    index: true
  },
  permissions: [{
    type: String,
    enum: [
      'read_dashboards',
      'read_agents',
      'manage_agents',
      'read_vulnerabilities',
      'manage_vulnerabilities',
      'read_scans',
      'manage_scans',
      'read_reports',
      'generate_reports',
      'manage_users',
      'system_admin'
    ]
  }],
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  lastLogin: {
    type: Date,
    index: true
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  emailVerificationToken: String,
  emailVerified: {
    type: Boolean,
    default: false
  },
  preferences: {
    theme: {
      type: String,
      enum: ['light', 'dark'],
      default: 'light'
    },
    language: {
      type: String,
      default: 'en'
    },
    timezone: {
      type: String,
      default: 'UTC'
    },
    notifications: {
      email: {
        type: Boolean,
        default: true
      },
      browser: {
        type: Boolean,
        default: true
      },
      criticalAlerts: {
        type: Boolean,
        default: true
      }
    },
    dashboard: {
      defaultTimeRange: {
        type: String,
        default: '24h'
      },
      refreshInterval: {
        type: Number,
        default: 60 // seconds
      }
    }
  },
  apiKeys: [{
    keyId: String,
    name: String,
    hashedKey: String,
    permissions: [String],
    lastUsed: Date,
    expiresAt: Date,
    isActive: {
      type: Boolean,
      default: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }]
}, {
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.passwordResetToken;
      delete ret.emailVerificationToken;
      delete ret.apiKeys;
      return ret;
    }
  },
  toObject: { virtuals: true }
});

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual for account locked status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Indexes
userSchema.index({ email: 1, isActive: 1 });
userSchema.index({ role: 1, isActive: 1 });
userSchema.index({ lastLogin: -1 });

// Pre-save middleware for password hashing
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Instance methods
userSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    throw error;
  }
};

userSchema.methods.incrementLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // If we're at max attempts and not locked yet, lock the account
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 hours
  }
  
  return this.updateOne(updates);
};

userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

userSchema.methods.updateLastLogin = function() {
  this.lastLogin = new Date();
  return this.save();
};

userSchema.methods.hasPermission = function(permission) {
  if (this.role === 'admin') return true;
  return this.permissions.includes(permission);
};

userSchema.methods.generateApiKey = function(name, permissions = []) {
  const crypto = require('crypto');
  const keyId = crypto.randomUUID();
  const apiKey = crypto.randomBytes(32).toString('hex');
  const hashedKey = crypto.createHash('sha256').update(apiKey).digest('hex');
  
  this.apiKeys.push({
    keyId,
    name,
    hashedKey,
    permissions,
    lastUsed: null,
    expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
    isActive: true
  });
  
  return { keyId, apiKey: `hbvm_${keyId}_${apiKey}` };
};

userSchema.methods.validateApiKey = function(apiKey) {
  if (!apiKey.startsWith('hbvm_')) return null;
  
  const parts = apiKey.split('_');
  if (parts.length !== 3) return null;
  
  const keyId = parts[1];
  const key = parts[2];
  
  const crypto = require('crypto');
  const hashedKey = crypto.createHash('sha256').update(key).digest('hex');
  
  const apiKeyDoc = this.apiKeys.find(ak => 
    ak.keyId === keyId && 
    ak.hashedKey === hashedKey && 
    ak.isActive && 
    (!ak.expiresAt || ak.expiresAt > new Date())
  );
  
  if (apiKeyDoc) {
    apiKeyDoc.lastUsed = new Date();
    this.save();
    return apiKeyDoc;
  }
  
  return null;
};

// Static methods
userSchema.statics.findByEmail = function(email) {
  return this.findOne({ email: email.toLowerCase(), isActive: true });
};

userSchema.statics.findByUsername = function(username) {
  return this.findOne({ username, isActive: true });
};

userSchema.statics.findByRole = function(role) {
  return this.find({ role, isActive: true });
};

// Role-based permission mapping
const rolePermissions = {
  admin: [
    'read_dashboards', 'read_agents', 'manage_agents', 'read_vulnerabilities',
    'manage_vulnerabilities', 'read_scans', 'manage_scans', 'read_reports',
    'generate_reports', 'manage_users', 'system_admin'
  ],
  analyst: [
    'read_dashboards', 'read_agents', 'read_vulnerabilities', 'manage_vulnerabilities',
    'read_scans', 'manage_scans', 'read_reports', 'generate_reports'
  ],
  operator: [
    'read_dashboards', 'read_agents', 'manage_agents', 'read_vulnerabilities',
    'read_scans', 'manage_scans', 'read_reports'
  ],
  viewer: [
    'read_dashboards', 'read_agents', 'read_vulnerabilities', 'read_scans', 'read_reports'
  ]
};

userSchema.pre('save', function(next) {
  if (this.isModified('role')) {
    this.permissions = rolePermissions[this.role] || [];
  }
  next();
});

module.exports = mongoose.model('User', userSchema);