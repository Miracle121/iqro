import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { User } from '../entities/user.entity';
import { RedisService } from '../../common/services/redis.service';

interface JwtPayload {
  sub: string;
  email: string;
  role: string;
  sessionId: string;
  type: 'access' | 'refresh' | 'mfa';
  iat: number;
  exp: number;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly redisService: RedisService,
    configService: ConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET'),
      passReqToCallback: true,
    });
  }

  async validate(req: any, payload: JwtPayload): Promise<User> {
    const { sub: userId, sessionId, type } = payload;

    // Only allow access tokens for authentication
    if (type !== 'access') {
      throw new UnauthorizedException('Invalid token type');
    }

    // Extract token from Authorization header
    const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
    if (!token) {
      throw new UnauthorizedException('Token not found');
    }

    // Check if token is blacklisted
    const isBlacklisted = await this.redisService.isBlacklisted(token);
    if (isBlacklisted) {
      throw new UnauthorizedException('Token has been revoked');
    }

    // Verify session exists
    const session = await this.redisService.getSession(sessionId);
    if (!session) {
      throw new UnauthorizedException('Session not found or expired');
    }

    // Find user
    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Check if user account is still active
    if (!user.isActive) {
      throw new UnauthorizedException('Account is not active');
    }

    // Update last activity
    user.lastActivityAt = new Date();
    await this.userRepository.save(user);

    return user;
  }
}