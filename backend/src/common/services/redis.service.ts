import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { RedisConfig } from '../../config/redis.config';

@Injectable()
export class RedisService implements OnModuleDestroy {
  private readonly redis: Redis;

  constructor(private readonly configService: ConfigService) {
    this.redis = new Redis(RedisConfig(configService));
  }

  async onModuleDestroy() {
    await this.redis.disconnect();
  }

  // Basic Redis operations
  async get(key: string): Promise<string | null> {
    return this.redis.get(key);
  }

  async set(key: string, value: string, ttl?: number): Promise<'OK'> {
    if (ttl) {
      return this.redis.setex(key, ttl, value);
    }
    return this.redis.set(key, value);
  }

  async del(key: string): Promise<number> {
    return this.redis.del(key);
  }

  async exists(key: string): Promise<number> {
    return this.redis.exists(key);
  }

  async expire(key: string, ttl: number): Promise<number> {
    return this.redis.expire(key, ttl);
  }

  async ttl(key: string): Promise<number> {
    return this.redis.ttl(key);
  }

  // JSON operations
  async setJson<T>(key: string, value: T, ttl?: number): Promise<'OK'> {
    const jsonValue = JSON.stringify(value);
    return this.set(key, jsonValue, ttl);
  }

  async getJson<T>(key: string): Promise<T | null> {
    const value = await this.get(key);
    return value ? JSON.parse(value) : null;
  }

  // Session management
  async storeSession(sessionId: string, sessionData: any, ttl: number = 3600): Promise<'OK'> {
    const key = `session:${sessionId}`;
    return this.setJson(key, sessionData, ttl);
  }

  async getSession<T>(sessionId: string): Promise<T | null> {
    const key = `session:${sessionId}`;
    return this.getJson<T>(key);
  }

  async deleteSession(sessionId: string): Promise<number> {
    const key = `session:${sessionId}`;
    return this.del(key);
  }

  async extendSession(sessionId: string, ttl: number): Promise<number> {
    const key = `session:${sessionId}`;
    return this.expire(key, ttl);
  }

  // MFA operations
  async storeMFAToken(userId: string, token: string, ttl: number = 300): Promise<'OK'> {
    const key = `mfa:${userId}`;
    return this.set(key, token, ttl);
  }

  async getMFAToken(userId: string): Promise<string | null> {
    const key = `mfa:${userId}`;
    return this.get(key);
  }

  async deleteMFAToken(userId: string): Promise<number> {
    const key = `mfa:${userId}`;
    return this.del(key);
  }

  // Rate limiting
  async incrementRateLimit(key: string, window: number): Promise<number> {
    const pipeline = this.redis.pipeline();
    pipeline.incr(key);
    pipeline.expire(key, window);
    const results = await pipeline.exec();
    return results[0][1] as number;
  }

  async getRateLimit(key: string): Promise<number> {
    const value = await this.get(key);
    return value ? parseInt(value, 10) : 0;
  }

  // Cache operations
  async cache<T>(key: string, fetchFunction: () => Promise<T>, ttl: number = 3600): Promise<T> {
    const cached = await this.getJson<T>(key);
    if (cached) {
      return cached;
    }

    const fresh = await fetchFunction();
    await this.setJson(key, fresh, ttl);
    return fresh;
  }

  // List operations
  async lpush(key: string, ...values: string[]): Promise<number> {
    return this.redis.lpush(key, ...values);
  }

  async rpop(key: string): Promise<string | null> {
    return this.redis.rpop(key);
  }

  async lrange(key: string, start: number, stop: number): Promise<string[]> {
    return this.redis.lrange(key, start, stop);
  }

  // Set operations
  async sadd(key: string, ...members: string[]): Promise<number> {
    return this.redis.sadd(key, ...members);
  }

  async srem(key: string, ...members: string[]): Promise<number> {
    return this.redis.srem(key, ...members);
  }

  async smembers(key: string): Promise<string[]> {
    return this.redis.smembers(key);
  }

  async sismember(key: string, member: string): Promise<number> {
    return this.redis.sismember(key, member);
  }

  // Active sessions tracking
  async addActiveSession(userId: string, sessionId: string): Promise<number> {
    const key = `active_sessions:${userId}`;
    return this.sadd(key, sessionId);
  }

  async removeActiveSession(userId: string, sessionId: string): Promise<number> {
    const key = `active_sessions:${userId}`;
    return this.srem(key, sessionId);
  }

  async getActiveSessions(userId: string): Promise<string[]> {
    const key = `active_sessions:${userId}`;
    return this.smembers(key);
  }

  async countActiveSessions(userId: string): Promise<number> {
    const sessions = await this.getActiveSessions(userId);
    return sessions.length;
  }

  // Blacklist operations
  async addToBlacklist(token: string, ttl: number): Promise<'OK'> {
    const key = `blacklist:${token}`;
    return this.set(key, 'true', ttl);
  }

  async isBlacklisted(token: string): Promise<boolean> {
    const key = `blacklist:${token}`;
    const exists = await this.exists(key);
    return exists === 1;
  }
}