import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { FusionAuthClient } from './fusionauth.client';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(private readonly fusionAuthClient: FusionAuthClient) {}

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
        accessToken: result.token,
        refreshToken: result.refreshToken,
        user: {
          id: result.user.id,
          email: result.user.email,
          username: result.user.username,
          firstName: result.user.firstName,
          lastName: result.user.lastName,
        },
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
}
