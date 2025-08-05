import {
  Controller,
  Post,
  Get,
  Put,
  Delete,
  Body,
  Req,
  HttpCode,
  HttpStatus,
  UseGuards,
  Param,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBadRequestResponse,
  ApiUnauthorizedResponse,
  ApiConflictResponse,
  ApiNotFoundResponse,
} from '@nestjs/swagger';
import { Request } from 'express';
import { ThrottlerGuard } from '@nestjs/throttler';

import { AuthService } from '../services/auth.service';
import { User } from '../entities/user.entity';
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

import {
  Public,
  Auth,
  AdminOnly,
  AuthenticatedUser,
  getCurrentUser,
} from '../decorators/auth.decorators';

@ApiTags('Authentication')
@Controller('auth')
@UseGuards(ThrottlerGuard)
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'User registered successfully', type: UserProfileDto })
  @ApiConflictResponse({ description: 'Username or email already exists' })
  @ApiBadRequestResponse({ description: 'Invalid input data' })
  async register(@Body() registerDto: RegisterDto): Promise<UserProfileDto> {
    return this.authService.register(registerDto);
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'User login' })
  @ApiResponse({ status: 200, description: 'Login successful', type: AuthResponseDto })
  @ApiUnauthorizedResponse({ description: 'Invalid credentials' })
  @ApiBadRequestResponse({ description: 'Invalid input data' })
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
  ): Promise<AuthResponseDto> {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const userAgent = req.get('User-Agent') || 'unknown';
    
    return this.authService.login(loginDto, ip, userAgent);
  }

  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({ status: 200, description: 'Token refreshed successfully', type: AuthResponseDto })
  @ApiUnauthorizedResponse({ description: 'Invalid refresh token' })
  async refresh(@Body() refreshTokenDto: RefreshTokenDto): Promise<AuthResponseDto> {
    return this.authService.refreshToken(refreshTokenDto);
  }

  @AuthenticatedUser()
  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'User logout' })
  @ApiResponse({ status: 204, description: 'Logout successful' })
  async logout(@Req() req: Request): Promise<void> {
    const user = getCurrentUser(req) as User;
    const token = req.get('Authorization')?.replace('Bearer ', '') || '';
    
    return this.authService.logout(user.id, token);
  }

  @AuthenticatedUser()
  @Get('profile')
  @ApiOperation({ summary: 'Get user profile' })
  @ApiResponse({ status: 200, description: 'User profile retrieved', type: UserProfileDto })
  async getProfile(@Req() req: Request): Promise<UserProfileDto> {
    const user = getCurrentUser(req) as User;
    return this.authService.getProfile(user.id);
  }

  @AuthenticatedUser()
  @Put('profile')
  @ApiOperation({ summary: 'Update user profile' })
  @ApiResponse({ status: 200, description: 'Profile updated successfully', type: UserProfileDto })
  @ApiBadRequestResponse({ description: 'Invalid input data' })
  async updateProfile(
    @Req() req: Request,
    @Body() updateProfileDto: UpdateProfileDto,
  ): Promise<UserProfileDto> {
    const user = getCurrentUser(req) as User;
    return this.authService.updateProfile(user.id, updateProfileDto);
  }

  @AuthenticatedUser()
  @Post('change-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Change user password' })
  @ApiResponse({ status: 204, description: 'Password changed successfully' })
  @ApiUnauthorizedResponse({ description: 'Current password is incorrect' })
  @ApiBadRequestResponse({ description: 'Invalid input data' })
  async changePassword(
    @Req() req: Request,
    @Body() changePasswordDto: ChangePasswordDto,
  ): Promise<void> {
    const user = getCurrentUser(req) as User;
    return this.authService.changePassword(user.id, changePasswordDto);
  }

  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Request password reset' })
  @ApiResponse({ status: 204, description: 'Password reset email sent' })
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto): Promise<void> {
    return this.authService.forgotPassword(forgotPasswordDto);
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Reset password with token' })
  @ApiResponse({ status: 204, description: 'Password reset successfully' })
  @ApiBadRequestResponse({ description: 'Invalid or expired reset token' })
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto): Promise<void> {
    return this.authService.resetPassword(resetPasswordDto);
  }

  // MFA Endpoints
  @AuthenticatedUser()
  @Post('mfa/setup')
  @ApiOperation({ summary: 'Setup MFA for user' })
  @ApiResponse({ status: 200, description: 'MFA setup initiated', type: MfaSetupResponseDto })
  @ApiBadRequestResponse({ description: 'MFA is already enabled' })
  async setupMfa(@Req() req: Request): Promise<MfaSetupResponseDto> {
    const user = getCurrentUser(req) as User;
    return this.authService.setupMfa(user.id);
  }

  @AuthenticatedUser()
  @Post('mfa/enable')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Enable MFA after verification' })
  @ApiResponse({ status: 204, description: 'MFA enabled successfully' })
  @ApiBadRequestResponse({ description: 'Invalid MFA token or setup session' })
  async enableMfa(
    @Req() req: Request,
    @Body() mfaSetupDto: MfaSetupDto,
  ): Promise<void> {
    const user = getCurrentUser(req) as User;
    return this.authService.enableMfa(user.id, mfaSetupDto);
  }

  @AuthenticatedUser()
  @Delete('mfa')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Disable MFA' })
  @ApiResponse({ status: 204, description: 'MFA disabled successfully' })
  @ApiUnauthorizedResponse({ description: 'Invalid password' })
  @ApiBadRequestResponse({ description: 'MFA is not enabled' })
  async disableMfa(
    @Req() req: Request,
    @Body('password') password: string,
  ): Promise<void> {
    const user = getCurrentUser(req) as User;
    return this.authService.disableMfa(user.id, password);
  }

  @Public()
  @Post('mfa/verify')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify MFA token during login' })
  @ApiResponse({ status: 200, description: 'MFA verified successfully', type: AuthResponseDto })
  @ApiUnauthorizedResponse({ description: 'Invalid MFA token' })
  async verifyMfa(
    @Body() mfaVerifyDto: MfaVerifyDto,
    @Req() req: Request,
  ): Promise<AuthResponseDto> {
    // This would be part of the login flow
    // Implementation depends on how MFA session is handled
    throw new Error('Not implemented - part of login flow');
  }

  // Admin endpoints for user management
  @AdminOnly()
  @Post('admin/users')
  @ApiOperation({ summary: 'Admin: Create new user' })
  @ApiResponse({ status: 201, description: 'User created successfully', type: UserProfileDto })
  @ApiConflictResponse({ description: 'Username or email already exists' })
  async createUser(
    @Body() registerDto: RegisterDto,
    @Req() req: Request,
  ): Promise<UserProfileDto> {
    const admin = getCurrentUser(req) as User;
    return this.authService.register(registerDto, admin.id);
  }
}