const mongoose = require('mongoose');

const agentSchema = new mongoose.Schema({
  agentId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  hostname: {
    type: String,
    required: true,
    index: true
  },
  osInfo: {
    name: String,
    version: String,
    codename: String,
    id: String,
    like: String,
    kernel: String,
    architecture: String
  },
  systemInfo: {
    cpuCount: Number,
    memoryTotal: Number,
    diskUsage: mongoose.Schema.Types.Mixed,
    networkInterfaces: [String],
    bootTime: Number
  },
  agentVersion: {
    type: String,
    required: true
  },
  capabilities: [{
    type: String,
    enum: ['vulnerability_scan', 'system_info', 'configuration_check', 'compliance_check']
  }],
  status: {
    type: String,
    enum: ['active', 'inactive', 'error', 'maintenance'],
    default: 'active',
    index: true
  },
  lastHeartbeat: {
    type: Date,
    default: Date.now,
    index: true
  },
  lastScanTime: {
    type: Date,
    index: true
  },
  scanInterval: {
    type: Number,
    default: 24 // hours
  },
  configuration: {
    scanEnabled: {
      type: Boolean,
      default: true
    },
    alertsEnabled: {
      type: Boolean,
      default: true
    },
    customSettings: mongoose.Schema.Types.Mixed
  },
  ipAddress: String,
  userAgent: String,
  location: {
    datacenter: String,
    region: String,
    zone: String
  },
  tags: [{
    key: String,
    value: String
  }]
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for agent status based on last heartbeat
agentSchema.virtual('isOnline').get(function() {
  if (!this.lastHeartbeat) return false;
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
  return this.lastHeartbeat > fiveMinutesAgo;
});

// Virtual for overdue scan detection
agentSchema.virtual('isScanOverdue').get(function() {
  if (!this.lastScanTime) return true;
  const scanIntervalMs = this.scanInterval * 60 * 60 * 1000;
  const nextScanDue = new Date(this.lastScanTime.getTime() + scanIntervalMs);
  return new Date() > nextScanDue;
});

// Index for efficient queries
agentSchema.index({ status: 1, lastHeartbeat: -1 });
agentSchema.index({ hostname: 1, status: 1 });
agentSchema.index({ 'osInfo.name': 1, 'osInfo.version': 1 });

// Pre-save middleware
agentSchema.pre('save', function(next) {
  if (this.isModified('lastHeartbeat')) {
    this.status = 'active';
  }
  next();
});

// Instance methods
agentSchema.methods.updateHeartbeat = function() {
  this.lastHeartbeat = new Date();
  this.status = 'active';
  return this.save();
};

agentSchema.methods.markScanCompleted = function() {
  this.lastScanTime = new Date();
  return this.save();
};

// Static methods
agentSchema.statics.findOnlineAgents = function() {
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
  return this.find({
    lastHeartbeat: { $gte: fiveMinutesAgo },
    status: 'active'
  });
};

agentSchema.statics.findOverdueScans = function() {
  return this.aggregate([
    {
      $addFields: {
        nextScanDue: {
          $add: [
            '$lastScanTime',
            { $multiply: ['$scanInterval', 60 * 60 * 1000] }
          ]
        }
      }
    },
    {
      $match: {
        $or: [
          { lastScanTime: null },
          { nextScanDue: { $lt: new Date() } }
        ],
        status: 'active'
      }
    }
  ]);
};

module.exports = mongoose.model('Agent', agentSchema);