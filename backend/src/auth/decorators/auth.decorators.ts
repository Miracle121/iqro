import { SetMetadata, applyDecorators, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiUnauthorizedResponse, ApiForbiddenResponse } from '@nestjs/swagger';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';
import { UserRole } from '../entities/user.entity';

export const IS_PUBLIC_KEY = 'isPublic';
export const ROLES_KEY = 'roles';

/**
 * Mark a route as public (no authentication required)
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

/**
 * Set required roles for a route
 */
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);

/**
 * Apply authentication to a route
 */
export const Auth = (...roles: UserRole[]) => {
  const decorators = [
    UseGuards(JwtAuthGuard, RolesGuard),
    ApiBearerAuth('JWT-auth'),
    ApiUnauthorizedResponse({ description: 'Unauthorized' }),
  ];

  if (roles.length > 0) {
    decorators.push(
      Roles(...roles),
      ApiForbiddenResponse({ description: 'Forbidden' })
    );
  }

  return applyDecorators(...decorators);
};

/**
 * Get current user from request
 */
export const getCurrentUser = (req: any) => req.user;

/**
 * Admin only access
 */
export const AdminOnly = () => Auth(UserRole.ADMIN);

/**
 * Admin or Auditor access
 */
export const AdminOrAuditor = () => Auth(UserRole.ADMIN, UserRole.AUDITOR);

/**
 * Any authenticated user
 */
export const AuthenticatedUser = () => Auth();