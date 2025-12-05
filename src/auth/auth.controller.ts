import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Res,
  Req,
  Get,
  UseGuards,
  UnauthorizedException,
} from '@nestjs/common';
import type { Response, Request } from 'express';
import * as jwt from 'jsonwebtoken';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
// import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * Signup endpoint
   * POST /auth/signup
   */
  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  async signup(@Body() signupDto: SignupDto) {
    return this.authService.signup(signupDto);
  }

  /**
   * Login endpoint
   * POST /auth/login
   * Returns JWT tokens and sets them in httpOnly cookies
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const result = await this.authService.login(loginDto);

    // Set tokens in httpOnly cookies for security
    response.cookie('accessToken', result.accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000, // 1 hour
    });

    response.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 604800000, // 7 days
    });

    return {
      message: 'Login successful',
      user: result.user,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    };
  }

  /**
   * Refresh token endpoint
   * POST /auth/refresh
   */
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Body() refreshTokenDto: RefreshTokenDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    const result = await this.authService.refreshToken(
      refreshTokenDto.refreshToken,
    );

    // Update cookies with new tokens
    response.cookie('accessToken', result.accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000, // 1 hour
    });

    response.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 604800000, // 7 days
    });

    return {
      message: 'Token refreshed successfully',
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    };
  }

  /**
   * Logout endpoint
   * POST /auth/logout
   * Extracts refresh token from cookie and revokes it in FusionAuth
   */
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    try {
      // Extract refresh token from cookie
      const refreshToken = request.cookies?.refreshToken;
      
      if (refreshToken) {
        // Revoke token in FusionAuth
        await this.authService.logout(refreshToken);
      }
    } catch (error) {
      // Log error but don't fail logout
      console.error('Failed to revoke token in FusionAuth:', error);
    }
    
    // Always clear cookies (even if FusionAuth call fails)
    response.clearCookie('accessToken');
    response.clearCookie('refreshToken');
    
    return {
      message: 'Logout successful',
    };
  }

  /**
   * Get current user endpoint
   * GET /auth/me
   * Decodes JWT to get user ID, then fetches user data from FusionAuth using API key
   */
  @Get('me')
  async getCurrentUser(@Req() request: Request) {
    try {
      // Extract JWT from cookie or Authorization header
      const token = request.cookies?.accessToken || 
                    request.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        throw new UnauthorizedException('No token provided');
      }

      // Decode JWT to get user ID (no verification needed)
      const decoded: any = jwt.decode(token);
      
      if (!decoded || !decoded.sub) {
        throw new UnauthorizedException('Invalid token');
      }

      const userId = decoded.sub;
      
      // Get user from FusionAuth using API key and user ID
      const user = await this.authService.getUserById(userId);
      
      return {
        user,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid token or failed to fetch user');
    }
  }

  /**
   * Get tenant members endpoint
   * GET /auth/members
   * Returns all users in the current tenant
   */
  @Get('members')
  async getTenantMembers(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    try {
      // Extract JWT from cookie or Authorization header for authentication
      const token = request.cookies?.accessToken || 
                    request.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        throw new UnauthorizedException('No token provided');
      }

      // Get query parameters for pagination
      const limit = parseInt(request.query?.limit as string) || 100;
      const startRow = parseInt(request.query?.startRow as string) || 0;

      // Fetch members from FusionAuth
      const result = await this.authService.getTenantMembers(limit, startRow);

      // Transform the response to match frontend expectations
      return {
        total: result.total,
        members: result.users.map((user: any) => ({
          id: user.id,
          email: user.email,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
          fullName: user.fullName || `${user.firstName || ''} ${user.lastName || ''}`.trim(),
          active: user.active,
          insertInstant: user.insertInstant,
          lastLoginInstant: user.lastLoginInstant,
          // Extract roles from registrations
          roles: user.registrations?.flatMap((reg: any) => reg.roles || []) || [],
          registrations: user.registrations,
        })),
      };
    } catch (error) {
      throw new UnauthorizedException('Failed to fetch tenant members');
    }
  }

  /**
   * Get tenant details endpoint
   * GET /auth/tenant
   * Returns current tenant information
   */
  @Get('tenant')
  async getTenantDetails(@Req() request: Request) {
    try {
      // Extract JWT from cookie or Authorization header for authentication
      const token = request.cookies?.accessToken || 
                    request.headers.authorization?.replace('Bearer ', '');
      
      if (!token) {
        throw new UnauthorizedException('No token provided');
      }

      // Fetch tenant details from FusionAuth
      const tenant = await this.authService.getTenantDetails();

      // Return tenant information
      return {
        tenant: {
          id: tenant.id,
          name: tenant.name,
          issuer: tenant.issuer,
          data: tenant.data,
          insertInstant: tenant.insertInstant,
          lastUpdateInstant: tenant.lastUpdateInstant,
        },
      };
    } catch (error) {
      throw new UnauthorizedException('Failed to fetch tenant details');
    }
  }

  /**
   * Initiate Google OAuth login
   * GET /auth/google
   * Redirects to FusionAuth OAuth endpoint with Google IdP hint
   */
  @Get('google')
  async googleLogin(@Res() response: Response) {
    try {
      const oauthUrl = await this.authService.getGoogleLoginUrl();
      response.redirect(oauthUrl);
    } catch (error) {
      throw new UnauthorizedException('Failed to initiate Google login');
    }
  }

  /**
   * Handle Google OAuth callback
   * GET /auth/google/callback
   * Exchanges authorization code for JWT tokens
   */
  @Get('google/callback')
  async googleCallback(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    try {
      const code = request.query?.code as string;
      
      if (!code) {
        throw new UnauthorizedException('Authorization code not provided');
      }

      // Exchange code for tokens
      const result = await this.authService.handleGoogleCallback(code);

      // Set tokens in httpOnly cookies
      response.cookie('accessToken', result.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 3600000, // 1 hour
      });

      response.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 604800000, // 7 days
      });

      // Redirect to frontend
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:8080';
      response.redirect(frontendUrl);
    } catch (error) {
      // Redirect to login with error
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:8080';
      response.redirect(`${frontendUrl}/login?error=google_auth_failed`);
    }
  }

  /**
   * Verify Google token and login user
   * POST /auth/google/verify
   * Direct Google OAuth - bypasses FusionAuth OAuth flow
   */
  @Post('google/verify')
  @HttpCode(HttpStatus.OK)
  async googleVerify(
    @Body() body: { token: string },
    @Res({ passthrough: true }) response: Response,
  ) {
    try {
      if (!body.token) {
        throw new UnauthorizedException('Google token not provided');
      }

      // Verify Google token and authenticate user
      const result = await this.authService.googleLogin(body.token);

      // Set tokens in httpOnly cookies
      response.cookie('accessToken', result.accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 3600000, // 1 hour
      });

      response.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 604800000, // 7 days
      });

      return {
        message: 'Google login successful',
        user: result.user,
      };
    } catch (error) {
      throw new UnauthorizedException(error.message || 'Google authentication failed');
    }
  }
}
