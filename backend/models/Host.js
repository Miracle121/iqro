const mongoose = require('mongoose');

const hostSchema = new mongoose.Schema({
    hostId: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    
    // Basic host information
    hostname: {
        type: String,
        required: true
    },
    
    // Operating system information
    osInfo: {
        distribution: String,
        version: String,
        kernel: String,
        architecture: String,
        platform: String
    },
    
    // Current risk assessment
    riskScore: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    },
    
    riskLevel: {
        type: String,
        enum: ['Low', 'Medium', 'High', 'Critical'],
        default: 'Low'
    },
    
    // Agent information
    agentInfo: {
        version: String,
        lastSeen: {
            type: Date,
            default: Date.now
        },
        status: {
            type: String,
            enum: ['online', 'offline', 'unknown'],
            default: 'unknown'
        }
    },
    
    // Network information
    network: {
        ipAddress: String,
        macAddress: String,
        openPorts: [{
            port: Number,
            protocol: String,
            service: String,
            version: String
        }]
    },
    
    // Vulnerability summary
    vulnerabilities: {
        total: {
            type: Number,
            default: 0
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
        lastScanDate: Date,
        lastUpdated: {
            type: Date,
            default: Date.now
        }
    },
    
    // Installed software summary
    software: {
        packages: [{
            name: String,
            version: String,
            packageManager: String
        }],
        services: [{
            name: String,
            version: String,
            status: String,
            port: Number
        }],
        lastInventoryDate: Date
    },
    
    // Configuration and metadata
    tags: [String],
    
    environment: {
        type: String,
        enum: ['production', 'staging', 'development', 'test'],
        default: 'production'
    },
    
    department: String,
    owner: String,
    
    // Compliance status
    compliance: {
        status: {
            type: String,
            enum: ['compliant', 'non-compliant', 'unknown'],
            default: 'unknown'
        },
        frameworks: [String], // e.g., ['PCI-DSS', 'HIPAA', 'SOX']
        lastAssessment: Date
    },
    
    // Audit fields
    createdAt: {
        type: Date,
        default: Date.now
    },
    
    updatedAt: {
        type: Date,
        default: Date.now
    },
    
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Indexes for performance
hostSchema.index({ riskScore: -1 });
hostSchema.index({ 'vulnerabilities.lastScanDate': -1 });
hostSchema.index({ 'agentInfo.lastSeen': -1 });
hostSchema.index({ riskLevel: 1 });
hostSchema.index({ environment: 1 });

// Virtual for risk severity distribution
hostSchema.virtual('riskDistribution').get(function() {
    const total = this.vulnerabilities.total;
    if (total === 0) return null;
    
    return {
        critical: Math.round((this.vulnerabilities.critical / total) * 100),
        high: Math.round((this.vulnerabilities.high / total) * 100),
        medium: Math.round((this.vulnerabilities.medium / total) * 100),
        low: Math.round((this.vulnerabilities.low / total) * 100)
    };
});

// Virtual for agent status
hostSchema.virtual('isOnline').get(function() {
    if (!this.agentInfo.lastSeen) return false;
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    return this.agentInfo.lastSeen > fiveMinutesAgo;
});

// Pre-save middleware to update timestamps and calculate risk level
hostSchema.pre('save', function(next) {
    this.updatedAt = new Date();
    
    // Update risk level based on score
    if (this.riskScore >= 80) {
        this.riskLevel = 'Critical';
    } else if (this.riskScore >= 60) {
        this.riskLevel = 'High';
    } else if (this.riskScore >= 30) {
        this.riskLevel = 'Medium';
    } else {
        this.riskLevel = 'Low';
    }
    
    // Update agent status based on last seen
    if (this.isOnline) {
        this.agentInfo.status = 'online';
    } else {
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        this.agentInfo.status = this.agentInfo.lastSeen > oneHourAgo ? 'offline' : 'unknown';
    }
    
    next();
});

// Static methods
hostSchema.statics.findByRiskLevel = function(riskLevel) {
    return this.find({ riskLevel, isActive: true });
};

hostSchema.statics.getHostsSummary = async function() {
    const pipeline = [
        { $match: { isActive: true } },
        {
            $group: {
                _id: null,
                totalHosts: { $sum: 1 },
                avgRiskScore: { $avg: '$riskScore' },
                criticalHosts: {
                    $sum: { $cond: [{ $eq: ['$riskLevel', 'Critical'] }, 1, 0] }
                },
                highRiskHosts: {
                    $sum: { $cond: [{ $eq: ['$riskLevel', 'High'] }, 1, 0] }
                },
                mediumRiskHosts: {
                    $sum: { $cond: [{ $eq: ['$riskLevel', 'Medium'] }, 1, 0] }
                },
                lowRiskHosts: {
                    $sum: { $cond: [{ $eq: ['$riskLevel', 'Low'] }, 1, 0] }
                },
                onlineHosts: {
                    $sum: { $cond: [{ $eq: ['$agentInfo.status', 'online'] }, 1, 0] }
                },
                totalVulnerabilities: { $sum: '$vulnerabilities.total' }
            }
        }
    ];
    
    const result = await this.aggregate(pipeline);
    return result[0] || {
        totalHosts: 0,
        avgRiskScore: 0,
        criticalHosts: 0,
        highRiskHosts: 0,
        mediumRiskHosts: 0,
        lowRiskHosts: 0,
        onlineHosts: 0,
        totalVulnerabilities: 0
    };
};

// Instance methods
hostSchema.methods.updateRiskScore = function(newScore) {
    this.riskScore = Math.min(100, Math.max(0, newScore));
    return this.save();
};

hostSchema.methods.addVulnerability = function(severity) {
    if (!this.vulnerabilities[severity]) return;
    
    this.vulnerabilities[severity]++;
    this.vulnerabilities.total++;
    this.vulnerabilities.lastUpdated = new Date();
    
    return this.save();
};

hostSchema.methods.updateAgentStatus = function(status, version) {
    this.agentInfo.status = status;
    this.agentInfo.lastSeen = new Date();
    if (version) {
        this.agentInfo.version = version;
    }
    
    return this.save();
};

module.exports = mongoose.model('Host', hostSchema);