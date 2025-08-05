import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';

import { User, UserRole, UserStatus } from '../entities/user.entity';
import { EncryptionService } from '../../common/services/encryption.service';
import { LoggerService } from '../../common/services/logger.service';
import { RedisService } from '../../common/services/redis.service';

import {
  LoginDto,
  RegisterDto,
  MfaSetupDto,
  MfaVerifyDto,
  ChangePasswordDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  RefreshTokenDto,
  UpdateProfileDto,
  AuthResponseDto,
  MfaSetupResponseDto,
  UserProfileDto,
} from '../dto/auth.dto';

interface JwtPayload {
  sub: string;
  email: string;
  role: UserRole;
  sessionId: string;
  type: 'access' | 'refresh' | 'mfa';
}

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly encryptionService: EncryptionService,
    private readonly loggerService: LoggerService,
    private readonly redisService: RedisService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async register(registerDto: RegisterDto, createdBy?: string): Promise<UserProfileDto> {
    const { username, email, password, ...userData } = registerDto;

    // Check if user already exists
    const existingUser = await this.userRepository.findOne({
      where: [{ username }, { email }],
    });

    if (existingUser) {
      throw new ConflictException('Username or email already exists');
    }

    // Hash password
    const passwordHash = await this.encryptionService.hashPassword(password);

    // Create user
    const user = this.userRepository.create({
      username,
      email,
      passwordHash,
      ...userData,
      createdBy,
      passwordLastChanged: new Date(),
    });

    const savedUser = await this.userRepository.save(user);

    this.loggerService.logSecurityEvent('USER_REGISTERED', savedUser.id, {
      username,
      email,
      role: userData.role || UserRole.USER,
      createdBy,
    });

    return this.toUserProfile(savedUser);
  }

  async login(loginDto: LoginDto, ip: string, userAgent: string): Promise<AuthResponseDto> {
    const { username, password, mfaToken, rememberMe } = loginDto;

    // Find user by username or email
    const user = await this.userRepository.findOne({
      where: [{ username }, { email: username }],
    });

    if (!user) {
      this.loggerService.logAuthentication('LOGIN_FAILED', username, ip, userAgent, false);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check account status
    await this.validateUserAccount(user);

    // Verify password
    const isPasswordValid = await this.encryptionService.verifyPassword(password, user.passwordHash);
    if (!isPasswordValid) {
      await this.handleFailedLogin(user, ip, userAgent);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Handle MFA if enabled
    if (user.mfaEnabled) {
      if (!mfaToken) {
        // Generate MFA session token
        const mfaSessionToken = this.encryptionService.generateSecureToken();
        await this.redisService.set(`mfa_session:${mfaSessionToken}`, user.id, 300); // 5 minutes

        this.loggerService.logAuthentication('MFA_REQUIRED', user.id, ip, userAgent);
        
        return {
          accessToken: '',
          refreshToken: '',
          tokenType: 'Bearer',
          expiresIn: 0,
          mfaRequired: true,
          mfaToken: mfaSessionToken,
        };
      }

      // Verify MFA token
      const mfaValid = await this.verifyMfaToken(user, mfaToken);
      if (!mfaValid) {
        this.loggerService.logAuthentication('MFA_FAILED', user.id, ip, userAgent, false);
        throw new UnauthorizedException('Invalid MFA token');
      }
    }

    // Generate tokens
    const tokens = await this.generateTokens(user, rememberMe);

    // Update user login info
    await this.updateLoginInfo(user, ip);

    // Reset failed login attempts
    if (user.failedLoginAttempts > 0) {
      user.failedLoginAttempts = 0;
      await this.userRepository.save(user);
    }

    this.loggerService.logAuthentication('LOGIN_SUCCESS', user.id, ip, userAgent, true);

    return tokens;
  }

  async refreshToken(refreshTokenDto: RefreshTokenDto): Promise<AuthResponseDto> {
    const { refreshToken } = refreshTokenDto;

    try {
      const payload = this.jwtService.verify(refreshToken) as JwtPayload;
      
      if (payload.type !== 'refresh') {
        throw new UnauthorizedException('Invalid token type');
      }

      // Check if token is blacklisted
      const isBlacklisted = await this.redisService.isBlacklisted(refreshToken);
      if (isBlacklisted) {
        throw new UnauthorizedException('Token has been revoked');
      }

      const user = await this.userRepository.findOne({ where: { id: payload.sub } });
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      await this.validateUserAccount(user);

      // Generate new tokens
      const tokens = await this.generateTokens(user);

      // Blacklist old refresh token
      const tokenExpiry = this.configService.get<string>('REFRESH_TOKEN_EXPIRES_IN', '7d');
      const ttl = this.parseDurationToSeconds(tokenExpiry);
      await this.redisService.addToBlacklist(refreshToken, ttl);

      this.loggerService.logSecurityEvent('TOKEN_REFRESHED', user.id);

      return tokens;
    } catch (error) {
      this.loggerService.logSecurityEvent('TOKEN_REFRESH_FAILED', null, { error: error.message });
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async setupMfa(userId: string): Promise<MfaSetupResponseDto> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.mfaEnabled) {
      throw new BadRequestException('MFA is already enabled');
    }

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `${this.configService.get<string>('MFA_ISSUER', 'PAM-System')} (${user.email})`,
      issuer: this.configService.get<string>('MFA_ISSUER', 'PAM-System'),
      length: 32,
    });

    // Generate QR code
    const qrCode = await qrcode.toDataURL(secret.otpauth_url);

    // Generate backup codes
    const backupCodes = Array.from({ length: 10 }, () =>
      this.encryptionService.generateSecureToken(8).toUpperCase()
    );

    // Store encrypted secret temporarily (user must verify before enabling)
    await this.redisService.setJson(`mfa_setup:${userId}`, {
      secret: secret.base32,
      backupCodes,
    }, 600); // 10 minutes

    this.loggerService.logSecurityEvent('MFA_SETUP_INITIATED', userId);

    return {
      qrCode,
      secret: secret.base32,
      backupCodes,
    };
  }

  async enableMfa(userId: string, mfaSetupDto: MfaSetupDto): Promise<void> {
    const { secret, token } = mfaSetupDto;

    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Get setup data from Redis
    const setupData = await this.redisService.getJson<{ secret: string; backupCodes: string[] }>(`mfa_setup:${userId}`);
    if (!setupData || setupData.secret !== secret) {
      throw new BadRequestException('Invalid MFA setup session');
    }

    // Verify token
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: this.configService.get<number>('MFA_WINDOW', 2),
    });

    if (!verified) {
      throw new BadRequestException('Invalid MFA token');
    }

    // Enable MFA
    user.mfaSecret = this.encryptionService.encrypt(secret);
    user.mfaEnabled = true;
    user.mfaBackupCodes = setupData.backupCodes.map(code => 
      this.encryptionService.encrypt(code)
    );

    await this.userRepository.save(user);

    // Clean up setup data
    await this.redisService.del(`mfa_setup:${userId}`);

    this.loggerService.logSecurityEvent('MFA_ENABLED', userId);
  }

  async disableMfa(userId: string, password: string): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (!user.mfaEnabled) {
      throw new BadRequestException('MFA is not enabled');
    }

    // Verify password
    const isPasswordValid = await this.encryptionService.verifyPassword(password, user.passwordHash);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    // Disable MFA
    user.mfaSecret = null;
    user.mfaEnabled = false;
    user.mfaBackupCodes = null;

    await this.userRepository.save(user);

    this.loggerService.logSecurityEvent('MFA_DISABLED', userId);
  }

  async verifyMfaToken(user: User, token: string, useBackupCode = false): Promise<boolean> {
    if (!user.mfaEnabled || !user.mfaSecret) {
      return false;
    }

    if (useBackupCode) {
      return this.verifyBackupCode(user, token);
    }

    const secret = this.encryptionService.decrypt(user.mfaSecret);
    
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: this.configService.get<number>('MFA_WINDOW', 2),
    });
  }

  async changePassword(userId: string, changePasswordDto: ChangePasswordDto): Promise<void> {
    const { currentPassword, newPassword, confirmPassword } = changePasswordDto;

    if (newPassword !== confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Verify current password
    const isCurrentPasswordValid = await this.encryptionService.verifyPassword(
      currentPassword,
      user.passwordHash
    );
    if (!isCurrentPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    // Hash new password
    const newPasswordHash = await this.encryptionService.hashPassword(newPassword);

    // Update password
    user.passwordHash = newPasswordHash;
    user.passwordLastChanged = new Date();
    user.requirePasswordChange = false;

    await this.userRepository.save(user);

    this.loggerService.logSecurityEvent('PASSWORD_CHANGED', userId);
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<void> {
    const { email } = forgotPasswordDto;

    const user = await this.userRepository.findOne({ where: { email } });
    // Don't reveal if email exists
    if (!user) {
      this.loggerService.logSecurityEvent('PASSWORD_RESET_REQUESTED', null, { email });
      return;
    }

    // Generate reset token
    const resetToken = this.encryptionService.generateSecureToken();
    await this.redisService.set(`password_reset:${resetToken}`, user.id, 3600); // 1 hour

    // TODO: Send email with reset link
    // await this.emailService.sendPasswordResetEmail(user.email, resetToken);

    this.loggerService.logSecurityEvent('PASSWORD_RESET_REQUESTED', user.id, { email });
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<void> {
    const { token, newPassword, confirmPassword } = resetPasswordDto;

    if (newPassword !== confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    const userId = await this.redisService.get(`password_reset:${token}`);
    if (!userId) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Hash new password
    const passwordHash = await this.encryptionService.hashPassword(newPassword);

    // Update password
    user.passwordHash = passwordHash;
    user.passwordLastChanged = new Date();
    user.requirePasswordChange = false;
    user.failedLoginAttempts = 0;
    user.lockedUntil = null;

    await this.userRepository.save(user);

    // Delete reset token
    await this.redisService.del(`password_reset:${token}`);

    this.loggerService.logSecurityEvent('PASSWORD_RESET_COMPLETED', userId);
  }

  async logout(userId: string, accessToken: string): Promise<void> {
    // Blacklist the access token
    const tokenExpiry = this.configService.get<string>('JWT_EXPIRES_IN', '1h');
    const ttl = this.parseDurationToSeconds(tokenExpiry);
    await this.redisService.addToBlacklist(accessToken, ttl);

    this.loggerService.logSecurityEvent('USER_LOGGED_OUT', userId);
  }

  async getProfile(userId: string): Promise<UserProfileDto> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.toUserProfile(user);
  }

  async updateProfile(userId: string, updateProfileDto: UpdateProfileDto): Promise<UserProfileDto> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    Object.assign(user, updateProfileDto);
    const updatedUser = await this.userRepository.save(user);

    this.loggerService.logSecurityEvent('PROFILE_UPDATED', userId, updateProfileDto);

    return this.toUserProfile(updatedUser);
  }

  // Private helper methods
  private async validateUserAccount(user: User): Promise<void> {
    if (user.status !== UserStatus.ACTIVE) {
      throw new ForbiddenException('Account is not active');
    }

    if (user.isLocked) {
      throw new ForbiddenException('Account is locked');
    }

    if (user.isExpired) {
      throw new ForbiddenException('Account has expired');
    }
  }

  private async handleFailedLogin(user: User, ip: string, userAgent: string): Promise<void> {
    user.failedLoginAttempts += 1;

    // Lock account after 5 failed attempts
    if (user.failedLoginAttempts >= 5) {
      user.lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
      this.loggerService.logSecurityEvent('ACCOUNT_LOCKED', user.id, {
        reason: 'Too many failed login attempts',
        ip,
      });
    }

    await this.userRepository.save(user);

    this.loggerService.logAuthentication('LOGIN_FAILED', user.id, ip, userAgent, false);
  }

  private async generateTokens(user: User, rememberMe = false): Promise<AuthResponseDto> {
    const sessionId = this.encryptionService.generateUUID();

    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      sessionId,
      type: 'access',
    };

    const accessTokenExpiry = this.configService.get<string>('JWT_EXPIRES_IN', '1h');
    const refreshTokenExpiry = rememberMe ? '30d' : this.configService.get<string>('REFRESH_TOKEN_EXPIRES_IN', '7d');

    const accessToken = this.jwtService.sign(payload, { expiresIn: accessTokenExpiry });
    const refreshToken = this.jwtService.sign(
      { ...payload, type: 'refresh' },
      { expiresIn: refreshTokenExpiry }
    );

    // Store session in Redis
    await this.redisService.storeSession(sessionId, {
      userId: user.id,
      accessToken,
      refreshToken,
      createdAt: new Date(),
    }, this.parseDurationToSeconds(refreshTokenExpiry));

    // Track active session
    await this.redisService.addActiveSession(user.id, sessionId);

    return {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: this.parseDurationToSeconds(accessTokenExpiry),
    };
  }

  private async updateLoginInfo(user: User, ip: string): Promise<void> {
    user.lastLoginAt = new Date();
    user.lastLoginIp = ip;
    user.lastActivityAt = new Date();
    await this.userRepository.save(user);
  }

  private async verifyBackupCode(user: User, code: string): Promise<boolean> {
    if (!user.mfaBackupCodes || user.mfaBackupCodes.length === 0) {
      return false;
    }

    const encryptedCode = this.encryptionService.encrypt(code.toUpperCase());
    const index = user.mfaBackupCodes.findIndex(backupCode => {
      try {
        const decryptedCode = this.encryptionService.decrypt(backupCode);
        return decryptedCode === code.toUpperCase();
      } catch {
        return false;
      }
    });

    if (index === -1) {
      return false;
    }

    // Remove used backup code
    user.mfaBackupCodes.splice(index, 1);
    await this.userRepository.save(user);

    this.loggerService.logSecurityEvent('MFA_BACKUP_CODE_USED', user.id);

    return true;
  }

  private toUserProfile(user: User): UserProfileDto {
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      fullName: user.fullName,
      role: user.role,
      phoneNumber: user.phoneNumber,
      department: user.department,
      jobTitle: user.jobTitle,
      mfaEnabled: user.mfaEnabled,
      lastLoginAt: user.lastLoginAt,
      lastActivityAt: user.lastActivityAt,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  private parseDurationToSeconds(duration: string): number {
    const units = {
      s: 1,
      m: 60,
      h: 3600,
      d: 86400,
    };

    const match = duration.match(/^(\d+)([smhd])$/);
    if (!match) {
      throw new Error(`Invalid duration format: ${duration}`);
    }

    const [, value, unit] = match;
    return parseInt(value, 10) * units[unit];
  }
}