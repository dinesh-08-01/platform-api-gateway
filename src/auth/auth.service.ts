import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OAuth2Client } from 'google-auth-library';
import { FusionAuthClient } from './fusionauth.client';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  private googleClient: OAuth2Client;

  constructor(
    private readonly fusionAuthClient: FusionAuthClient,
    private readonly configService: ConfigService,
  ) {
    // Initialize Google OAuth client
    const googleClientId = this.configService.get<string>('GOOGLE_CLIENT_ID');
    this.googleClient = new OAuth2Client(googleClientId);
  }

  /**
   * Register a new user
   */
  async signup(signupDto: SignupDto) {
    try {
      const result = await this.fusionAuthClient.register(
        signupDto.email,
        signupDto.password,
      );

      return {
        message: 'Signup successful',
        user: {
          id: result.user.id,
          email: result.user.email,
        },
      };
    } catch (error) {
      throw new BadRequestException(error.message || 'Signup failed');
    }
  }

  /**
   * Login user and return JWT tokens
   */
  async login(loginDto: LoginDto) {
    try {
      const result = await this.fusionAuthClient.login(
        loginDto.email,
        loginDto.password,
      );

      return {
        accessToken: result?.token || '',
        refreshToken: result?.refreshToken || '',
        user: result?.user || { id: '', email: ''},
      };
    } catch (error) {
      throw new UnauthorizedException(error.message || 'Invalid credentials');
    }
  }

  /**
   * Refresh access token
   */
  async refreshToken(refreshToken: string) {
    try {
      const result = await this.fusionAuthClient.refreshToken(refreshToken);

      return {
        accessToken: result.token,
        refreshToken: result.refreshToken,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  /**
   * Logout user
   */
  async logout(refreshToken: string) {
    try {
      await this.fusionAuthClient.logout(refreshToken);

      return {
        message: 'Logout successful',
      };
    } catch (error) {
      throw new BadRequestException('Logout failed');
    }
  }

  /**
   * Validate JWT token
   */
  async validateToken(token: string) {
    try {
      return await this.fusionAuthClient.validateToken(token);
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  /**
   * Get user details from FusionAuth using JWT
   */
  async getUserFromFusionAuth(jwt: string) {
    try {
      return await this.fusionAuthClient.getUserByJwt(jwt);
    } catch (error) {
      throw new UnauthorizedException('Failed to fetch user details');
    }
  }

  /**
   * Get user by ID from FusionAuth using API key
   */
  async getUserById(userId: string) {
    try {
      return await this.fusionAuthClient.getUserById(userId);
    } catch (error) {
      throw new UnauthorizedException('Failed to fetch user details');
    }
  }

  /**
   * Get all members of the tenant
   */
  async getTenantMembers(limit: number = 100, startRow: number = 0) {
    try {
      return await this.fusionAuthClient.searchUsers('*', limit, startRow);
    } catch (error) {
      throw new UnauthorizedException('Failed to fetch tenant members');
    }
  }

  /**
   * Get current tenant details
   */
  async getTenantDetails() {
    try {
      return await this.fusionAuthClient.getCurrentTenant();
    } catch (error) {
      throw new UnauthorizedException('Failed to fetch tenant details');
    }
  }

  /**
   * Get Google OAuth login URL
   */
  async getGoogleLoginUrl(): Promise<string> {
    const redirectUri = this.configService.get<string>('GOOGLE_REDIRECT_URI') || 'http://localhost:3000/api/auth/google/callback';
    return await this.fusionAuthClient.getGoogleLoginUrl(redirectUri);
  }

  /**
   * Handle Google OAuth callback
   */
  async handleGoogleCallback(code: string) {
    try {
      const redirectUri = this.configService.get<string>('GOOGLE_REDIRECT_URI') || 'http://localhost:3000/api/auth/google/callback';
      const result = await this.fusionAuthClient.exchangeOAuthCode(code, redirectUri);

      return {
        accessToken: result.access_token,
        refreshToken: result.refresh_token,
        user: result.user || {},
      };
    } catch (error) {
      throw new UnauthorizedException('Google authentication failed');
    }
  }

  /**
   * Verify Google token and authenticate user
   * Direct Google OAuth flow - bypasses FusionAuth OAuth
   */
  async googleLogin(googleToken: string) {
    try {
      // 1. Verify Google token
      const ticket = await this.googleClient.verifyIdToken({
        idToken: googleToken,
        audience: this.configService.get<string>('GOOGLE_CLIENT_ID'),
      });

      const payload = ticket.getPayload();
      
      if (!payload || !payload.email) {
        throw new UnauthorizedException('Invalid Google token');
      }

      // 2. Check if user exists in FusionAuth tenant
      const fusionAuthUser = await this.fusionAuthClient.findUserByEmail(payload.email);

      if (!fusionAuthUser) {
        throw new UnauthorizedException(`User with email ${payload.email} not found in tenant`);
      }

      // 3. Generate FusionAuth JWT for this user
      const tokens = await this.fusionAuthClient.generateJWTForUser(fusionAuthUser.id);

      // 4. Get full user details
      const userDetails = await this.fusionAuthClient.getUserById(fusionAuthUser.id);

      return {
        accessToken: tokens.token,
        refreshToken: tokens.refreshToken,
        user: userDetails,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Google authentication failed: ' + error.message);
    }
  }
}
