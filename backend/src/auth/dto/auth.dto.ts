import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MinLength,
  MaxLength,
  IsOptional,
  IsEnum,
  IsBoolean,
  IsArray,
  Matches,
} from 'class-validator';
import { UserRole } from '../entities/user.entity';

export class LoginDto {
  @ApiProperty({ description: 'Username or email', example: 'john.doe' })
  @IsNotEmpty()
  @IsString()
  username: string;

  @ApiProperty({ description: 'Password', example: 'SecurePassword123!' })
  @IsNotEmpty()
  @IsString()
  password: string;

  @ApiProperty({ description: 'Remember me option', default: false })
  @IsOptional()
  @IsBoolean()
  rememberMe?: boolean;

  @ApiProperty({ description: 'MFA token', example: '123456' })
  @IsOptional()
  @IsString()
  @MinLength(6)
  @MaxLength(6)
  mfaToken?: string;
}

export class RegisterDto {
  @ApiProperty({ description: 'Username', example: 'john.doe' })
  @IsNotEmpty()
  @IsString()
  @MinLength(3)
  @MaxLength(50)
  @Matches(/^[a-zA-Z0-9._-]+$/, {
    message: 'Username can only contain letters, numbers, dots, underscores, and hyphens',
  })
  username: string;

  @ApiProperty({ description: 'Email address', example: 'john.doe@company.com' })
  @IsNotEmpty()
  @IsEmail()
  @MaxLength(255)
  email: string;

  @ApiProperty({ description: 'Password', example: 'SecurePassword123!' })
  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
  })
  password: string;

  @ApiProperty({ description: 'First name', example: 'John' })
  @IsNotEmpty()
  @IsString()
  @MaxLength(100)
  firstName: string;

  @ApiProperty({ description: 'Last name', example: 'Doe' })
  @IsNotEmpty()
  @IsString()
  @MaxLength(100)
  lastName: string;

  @ApiProperty({ description: 'User role', enum: UserRole })
  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;

  @ApiProperty({ description: 'Phone number', example: '+1-555-0123' })
  @IsOptional()
  @IsString()
  @MaxLength(20)
  phoneNumber?: string;

  @ApiProperty({ description: 'Department', example: 'IT Security' })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  department?: string;

  @ApiProperty({ description: 'Job title', example: 'Security Administrator' })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  jobTitle?: string;

  @ApiProperty({ description: 'Manager ID' })
  @IsOptional()
  @IsString()
  managerId?: string;
}

export class MfaSetupDto {
  @ApiProperty({ description: 'MFA secret from QR code scan' })
  @IsNotEmpty()
  @IsString()
  secret: string;

  @ApiProperty({ description: 'Verification token', example: '123456' })
  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  @MaxLength(6)
  token: string;
}

export class MfaVerifyDto {
  @ApiProperty({ description: 'MFA token', example: '123456' })
  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  @MaxLength(6)
  token: string;

  @ApiProperty({ description: 'Use backup code instead of TOTP' })
  @IsOptional()
  @IsBoolean()
  useBackupCode?: boolean;
}

export class ChangePasswordDto {
  @ApiProperty({ description: 'Current password' })
  @IsNotEmpty()
  @IsString()
  currentPassword: string;

  @ApiProperty({ description: 'New password', example: 'NewSecurePassword123!' })
  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
  })
  newPassword: string;

  @ApiProperty({ description: 'Confirm new password' })
  @IsNotEmpty()
  @IsString()
  confirmPassword: string;
}

export class ForgotPasswordDto {
  @ApiProperty({ description: 'Email address', example: 'john.doe@company.com' })
  @IsNotEmpty()
  @IsEmail()
  email: string;
}

export class ResetPasswordDto {
  @ApiProperty({ description: 'Reset token from email' })
  @IsNotEmpty()
  @IsString()
  token: string;

  @ApiProperty({ description: 'New password', example: 'NewSecurePassword123!' })
  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  @MaxLength(128)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
  })
  newPassword: string;

  @ApiProperty({ description: 'Confirm new password' })
  @IsNotEmpty()
  @IsString()
  confirmPassword: string;
}

export class RefreshTokenDto {
  @ApiProperty({ description: 'Refresh token' })
  @IsNotEmpty()
  @IsString()
  refreshToken: string;
}

export class OAuth2CallbackDto {
  @ApiProperty({ description: 'OAuth2 authorization code' })
  @IsNotEmpty()
  @IsString()
  code: string;

  @ApiProperty({ description: 'OAuth2 state parameter' })
  @IsNotEmpty()
  @IsString()
  state: string;
}

export class UpdateProfileDto {
  @ApiProperty({ description: 'First name', example: 'John' })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  firstName?: string;

  @ApiProperty({ description: 'Last name', example: 'Doe' })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  lastName?: string;

  @ApiProperty({ description: 'Phone number', example: '+1-555-0123' })
  @IsOptional()
  @IsString()
  @MaxLength(20)
  phoneNumber?: string;

  @ApiProperty({ description: 'Department', example: 'IT Security' })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  department?: string;

  @ApiProperty({ description: 'Job title', example: 'Security Administrator' })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  jobTitle?: string;
}

// Response DTOs
export class AuthResponseDto {
  @ApiProperty({ description: 'Access token' })
  accessToken: string;

  @ApiProperty({ description: 'Refresh token' })
  refreshToken: string;

  @ApiProperty({ description: 'Token type', example: 'Bearer' })
  tokenType: string;

  @ApiProperty({ description: 'Token expires in seconds', example: 3600 })
  expiresIn: number;

  @ApiProperty({ description: 'MFA required', default: false })
  mfaRequired?: boolean;

  @ApiProperty({ description: 'MFA token for next step' })
  mfaToken?: string;
}

export class MfaSetupResponseDto {
  @ApiProperty({ description: 'QR code data URL' })
  qrCode: string;

  @ApiProperty({ description: 'Manual entry secret' })
  secret: string;

  @ApiProperty({ description: 'Backup codes' })
  backupCodes: string[];
}

export class UserProfileDto {
  @ApiProperty({ description: 'User ID' })
  id: string;

  @ApiProperty({ description: 'Username' })
  username: string;

  @ApiProperty({ description: 'Email address' })
  email: string;

  @ApiProperty({ description: 'First name' })
  firstName: string;

  @ApiProperty({ description: 'Last name' })
  lastName: string;

  @ApiProperty({ description: 'Full name' })
  fullName: string;

  @ApiProperty({ description: 'User role' })
  role: UserRole;

  @ApiProperty({ description: 'Phone number' })
  phoneNumber?: string;

  @ApiProperty({ description: 'Department' })
  department?: string;

  @ApiProperty({ description: 'Job title' })
  jobTitle?: string;

  @ApiProperty({ description: 'MFA enabled status' })
  mfaEnabled: boolean;

  @ApiProperty({ description: 'Last login time' })
  lastLoginAt?: Date;

  @ApiProperty({ description: 'Last activity time' })
  lastActivityAt?: Date;

  @ApiProperty({ description: 'Creation timestamp' })
  createdAt: Date;

  @ApiProperty({ description: 'Last update timestamp' })
  updatedAt: Date;
}