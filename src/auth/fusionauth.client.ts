import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';

export interface FusionAuthLoginResponse {
  token: string;
  refreshToken: string;
  user: {
    id: string;
    email: string;
    username?: string;
    firstName?: string;
    lastName?: string;
  };
}

export interface FusionAuthRegistrationResponse {
  user: {
    id: string;
    email: string;
  };
}

export interface FusionAuthRefreshResponse {
  token: string;
  refreshToken: string;
}

@Injectable()
export class FusionAuthClient {
  private readonly logger = new Logger(FusionAuthClient.name);
  private readonly fusionAuthUrl: string;
  private readonly apiKey: string;
  private readonly applicationId: string;
  private readonly tenantId: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
  ) {
    this.fusionAuthUrl = this.configService.get<string>('FUSIONAUTH_URL') || '';
    this.apiKey = this.configService.get<string>('FUSIONAUTH_API_KEY') || '';
    this.applicationId = this.configService.get<string>('FUSIONAUTH_APPLICATION_ID') || '';
    this.tenantId = this.configService.get<string>('FUSIONAUTH_TENANT_ID') || '';
  }

  /**
   * Register a new user in FusionAuth
   */
  async register(email: string, password: string): Promise<FusionAuthRegistrationResponse> {
    try {
      const url = `${this.fusionAuthUrl}/api/user/registration`;
      
      const response = await firstValueFrom(
        this.httpService.post(
          url,
          {
            user: {
              email,
              password,
            },
            registration: {
              applicationId: this.applicationId,
            },
            skipVerification: true, // Set to false if you want email verification
          },
          {
            headers: {
              'Authorization': this.apiKey,
              'Content-Type': 'application/json',
              'X-FusionAuth-TenantId': this.tenantId,
            },
          },
        ),
      );

      this.logger.log(`User registered successfully: ${email}`);
      return response.data;
    } catch (error) {
      this.logger.error(`Registration failed: ${error.response?.data?.message || error.message}`);
      throw new Error(error.response?.data?.message || 'Registration failed');
    }
  }

  /**
   * Login user and get JWT tokens
   */
  async login(email: string, password: string): Promise<FusionAuthLoginResponse> {
    try {
      const url = `${this.fusionAuthUrl}/api/login`;
      
      const response = await firstValueFrom(
        this.httpService.post(
          url,
          {
            loginId: email,
            password,
            applicationId: this.applicationId,
          },
          {
            headers: {
              'Authorization': this.apiKey,
              'Content-Type': 'application/json',
              'X-FusionAuth-TenantId': this.tenantId,
            },
          },
        ),
      );

      this.logger.log(`User logged in successfully: ${email}`);
      return response.data;
    } catch (error) {
      this.logger.error(`Login failed: ${error.response?.data?.message || error.message}`);
      throw new Error(error.response?.data?.message || 'Invalid credentials');
    }
  }

  /**
   * Refresh JWT token
   */
  async refreshToken(refreshToken: string): Promise<FusionAuthRefreshResponse> {
    try {
      const url = `${this.fusionAuthUrl}/api/jwt/refresh`;
      
      const response = await firstValueFrom(
        this.httpService.post(
          url,
          {
            refreshToken,
          },
          {
            headers: {
              'Authorization': this.apiKey,
              'Content-Type': 'application/json',
              'X-FusionAuth-TenantId': this.tenantId,
            },
          },
        ),
      );

      this.logger.log('Token refreshed successfully');
      return response.data;
    } catch (error) {
      this.logger.error(`Token refresh failed: ${error.response?.data?.message || error.message}`);
      throw new Error('Token refresh failed');
    }
  }

  /**
   * Logout user (revoke refresh token)
   */
  async logout(refreshToken: string): Promise<void> {
    try {
      const url = `${this.fusionAuthUrl}/api/jwt/refresh`;
      
      await firstValueFrom(
        this.httpService.delete(url, {
          headers: {
            'Authorization': this.apiKey,
            'Content-Type': 'application/json',
            'X-FusionAuth-TenantId': this.tenantId,
          },
          data: {
            refreshToken,
          },
        }),
      );

      this.logger.log('User logged out successfully');
    } catch (error) {
      this.logger.error(`Logout failed: ${error.response?.data?.message || error.message}`);
      throw new Error('Logout failed');
    }
  }

  /**
   * Validate JWT token
   */
  async validateToken(token: string): Promise<any> {
    try {
      const url = `${this.fusionAuthUrl}/api/jwt/validate`;
      
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'X-FusionAuth-TenantId': this.tenantId,
          },
        }),
      );

      return response.data;
    } catch (error) {
      this.logger.error(`Token validation failed: ${error.message}`);
      throw new Error('Invalid token');
    }
  }
}
