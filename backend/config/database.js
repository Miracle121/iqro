const mongoose = require('mongoose');
const logger = require('./logger');

class Database {
    constructor() {
        this.connection = null;
        this.isConnected = false;
    }

    async connect() {
        try {
            const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/hbvm';
            
            const options = {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                maxPoolSize: 10,
                serverSelectionTimeoutMS: 5000,
                socketTimeoutMS: 45000,
                bufferCommands: false,
                bufferMaxEntries: 0
            };

            this.connection = await mongoose.connect(mongoUri, options);
            this.isConnected = true;

            logger.info(`MongoDB connected: ${this.connection.connection.host}`);

            // Handle connection events
            mongoose.connection.on('connected', () => {
                logger.info('MongoDB connected');
                this.isConnected = true;
            });

            mongoose.connection.on('error', (err) => {
                logger.error('MongoDB connection error:', err);
                this.isConnected = false;
            });

            mongoose.connection.on('disconnected', () => {
                logger.warn('MongoDB disconnected');
                this.isConnected = false;
            });

            // Handle process termination
            process.on('SIGINT', this.disconnect.bind(this));
            process.on('SIGTERM', this.disconnect.bind(this));

            return this.connection;

        } catch (error) {
            logger.error('Database connection failed:', error);
            this.isConnected = false;
            throw error;
        }
    }

    async disconnect() {
        try {
            if (this.connection) {
                await mongoose.connection.close();
                this.isConnected = false;
                logger.info('MongoDB connection closed');
            }
        } catch (error) {
            logger.error('Error closing MongoDB connection:', error);
        }
    }

    getConnection() {
        return this.connection;
    }

    isHealthy() {
        return this.isConnected && mongoose.connection.readyState === 1;
    }

    async ping() {
        try {
            await mongoose.connection.db.admin().ping();
            return true;
        } catch (error) {
            logger.error('Database ping failed:', error);
            return false;
        }
    }
}

module.exports = new Database();