const mongoose = require('mongoose');

const scanResultSchema = new mongoose.Schema({
  scanId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  agentId: {
    type: String,
    required: true,
    index: true
  },
  hostname: {
    type: String,
    required: true,
    index: true
  },
  scanTimestamp: {
    type: Date,
    required: true,
    index: true
  },
  scanDuration: {
    type: Number, // in seconds
    required: true
  },
  scanType: {
    type: String,
    enum: ['scheduled', 'manual', 'triggered'],
    default: 'scheduled',
    index: true
  },
  status: {
    type: String,
    enum: ['completed', 'failed', 'partial', 'processing'],
    default: 'completed',
    index: true
  },
  hostInfo: {
    hostname: String,
    os: {
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
    }
  },
  vulnerabilities: [{
    cveId: String,
    packageName: String,
    installedVersion: String,
    severity: {
      type: String,
      enum: ['critical', 'high', 'medium', 'low', 'informational']
    },
    cvssScore: Number,
    description: String,
    affectedVersions: [String],
    detectionMethod: String,
    component: String,
    file: String,
    permissions: String,
    riskScore: Number,
    exploitable: {
      type: Boolean,
      default: false
    },
    patchAvailable: {
      type: Boolean,
      default: false
    }
  }],
  summary: {
    totalVulnerabilities: {
      type: Number,
      default: 0,
      index: true
    },
    critical: {
      type: Number,
      default: 0
    },
    high: {
      type: Number,
      default: 0
    },
    medium: {
      type: Number,
      default: 0
    },
    low: {
      type: Number,
      default: 0
    },
    informational: {
      type: Number,
      default: 0
    }
  },
  riskMetrics: {
    overallRiskScore: {
      type: Number,
      min: 0,
      max: 10,
      index: true
    },
    exploitabilityScore: Number,
    exposureScore: Number,
    patchScore: Number,
    complianceScore: Number
  },
  packagesScanned: {
    type: Number,
    default: 0
  },
  error: {
    message: String,
    stack: String,
    code: String
  },
  processingMetadata: {
    enrichmentStatus: {
      type: String,
      enum: ['pending', 'completed', 'failed'],
      default: 'pending'
    },
    enrichmentTimestamp: Date,
    cveEnrichmentCount: {
      type: Number,
      default: 0
    },
    riskCalculationTimestamp: Date
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for scan age
scanResultSchema.virtual('scanAge').get(function() {
  const diffTime = Math.abs(new Date() - this.scanTimestamp);
  return Math.floor(diffTime / (1000 * 60 * 60 * 24)); // days
});

// Virtual for critical findings
scanResultSchema.virtual('criticalFindings').get(function() {
  return this.vulnerabilities.filter(v => v.severity === 'critical').length;
});

// Virtual for exploitable vulnerabilities
scanResultSchema.virtual('exploitableCount').get(function() {
  return this.vulnerabilities.filter(v => v.exploitable === true).length;
});

// Virtual for unpatched vulnerabilities
scanResultSchema.virtual('unpatchedCount').get(function() {
  return this.vulnerabilities.filter(v => v.patchAvailable === false).length;
});

// Indexes for efficient querying
scanResultSchema.index({ agentId: 1, scanTimestamp: -1 });
scanResultSchema.index({ hostname: 1, scanTimestamp: -1 });
scanResultSchema.index({ scanTimestamp: -1 });
scanResultSchema.index({ status: 1, scanTimestamp: -1 });
scanResultSchema.index({ 'riskMetrics.overallRiskScore': -1 });
scanResultSchema.index({ 'summary.totalVulnerabilities': -1 });
scanResultSchema.index({ 'summary.critical': -1, 'summary.high': -1 });

// Compound indexes
scanResultSchema.index({ 
  agentId: 1, 
  scanTimestamp: -1, 
  status: 1 
});

// Pre-save middleware to calculate summary
scanResultSchema.pre('save', function(next) {
  if (this.isModified('vulnerabilities')) {
    this.summary = {
      totalVulnerabilities: this.vulnerabilities.length,
      critical: this.vulnerabilities.filter(v => v.severity === 'critical').length,
      high: this.vulnerabilities.filter(v => v.severity === 'high').length,
      medium: this.vulnerabilities.filter(v => v.severity === 'medium').length,
      low: this.vulnerabilities.filter(v => v.severity === 'low').length,
      informational: this.vulnerabilities.filter(v => v.severity === 'informational').length
    };
  }
  next();
});

// Instance methods
scanResultSchema.methods.calculateRiskScore = function() {
  const vulnerabilities = this.vulnerabilities;
  if (!vulnerabilities || vulnerabilities.length === 0) {
    this.riskMetrics.overallRiskScore = 0;
    return 0;
  }

  // Base score calculation using CVSS scores
  const avgCvssScore = vulnerabilities.reduce((sum, v) => {
    return sum + (v.cvssScore || 0);
  }, 0) / vulnerabilities.length;

  // Severity weighting
  const severityWeights = { critical: 10, high: 7, medium: 4, low: 2, informational: 1 };
  const weightedScore = vulnerabilities.reduce((sum, v) => {
    return sum + (severityWeights[v.severity] || 1);
  }, 0) / vulnerabilities.length;

  // Exploitability factor
  const exploitableCount = this.exploitableCount;
  const exploitabilityFactor = exploitableCount > 0 ? 1 + (exploitableCount / vulnerabilities.length) : 1;

  // Patch availability factor (inverse)
  const unpatchedCount = this.unpatchedCount;
  const patchFactor = unpatchedCount > 0 ? 1 + (unpatchedCount / vulnerabilities.length * 0.5) : 1;

  // Calculate overall risk score
  const riskScore = Math.min(10, (avgCvssScore * 0.4 + weightedScore * 0.4) * exploitabilityFactor * patchFactor);

  this.riskMetrics = {
    overallRiskScore: Math.round(riskScore * 10) / 10,
    exploitabilityScore: exploitabilityFactor,
    exposureScore: weightedScore,
    patchScore: patchFactor,
    complianceScore: 10 - riskScore // Inverse relationship
  };

  return this.riskMetrics.overallRiskScore;
};

// Static methods
scanResultSchema.statics.findByAgent = function(agentId, limit = 10) {
  return this.find({ agentId })
    .sort({ scanTimestamp: -1 })
    .limit(limit);
};

scanResultSchema.statics.findLatestScans = function(limit = 50) {
  return this.find({ status: 'completed' })
    .sort({ scanTimestamp: -1 })
    .limit(limit);
};

scanResultSchema.statics.findHighRiskHosts = function(threshold = 7) {
  return this.find({
    'riskMetrics.overallRiskScore': { $gte: threshold },
    status: 'completed'
  }).sort({ 'riskMetrics.overallRiskScore': -1 });
};

scanResultSchema.statics.getAgentRiskTrend = function(agentId, days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  return this.aggregate([
    {
      $match: {
        agentId,
        scanTimestamp: { $gte: startDate },
        status: 'completed'
      }
    },
    {
      $group: {
        _id: {
          $dateToString: {
            format: '%Y-%m-%d',
            date: '$scanTimestamp'
          }
        },
        avgRiskScore: { $avg: '$riskMetrics.overallRiskScore' },
        totalVulns: { $avg: '$summary.totalVulnerabilities' },
        criticalCount: { $avg: '$summary.critical' },
        scanCount: { $sum: 1 }
      }
    },
    { $sort: { _id: 1 } }
  ]);
};

scanResultSchema.statics.getVulnerabilityTrends = function(days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  return this.aggregate([
    {
      $match: {
        scanTimestamp: { $gte: startDate },
        status: 'completed'
      }
    },
    {
      $group: {
        _id: {
          $dateToString: {
            format: '%Y-%m-%d',
            date: '$scanTimestamp'
          }
        },
        totalScans: { $sum: 1 },
        avgVulnerabilities: { $avg: '$summary.totalVulnerabilities' },
        avgRiskScore: { $avg: '$riskMetrics.overallRiskScore' },
        criticalSum: { $sum: '$summary.critical' },
        highSum: { $sum: '$summary.high' },
        mediumSum: { $sum: '$summary.medium' },
        lowSum: { $sum: '$summary.low' }
      }
    },
    { $sort: { _id: 1 } }
  ]);
};

module.exports = mongoose.model('ScanResult', scanResultSchema);