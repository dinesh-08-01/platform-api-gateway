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
            noJWT: false,  // Ensure JWT is generated
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
      this.logger.log(`FusionAuth response:`, JSON.stringify(response.data));
      
      // Check if refresh token is present
      if (!response.data.refreshToken) {
        this.logger.warn(`No refresh token in response. Check FusionAuth application JWT settings.`);
      }
      
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

  /**
   * Get user details by JWT token
   */
  async getUserByJwt(jwt: string): Promise<any> {
    try {
      const url = `${this.fusionAuthUrl}/api/user`;
      
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: {
            'Authorization': `Bearer ${jwt}`,
            'X-FusionAuth-TenantId': this.tenantId,
          },
        }),
      );

      this.logger.log('User details fetched from FusionAuth');
      return response.data.user;
    } catch (error) {
      this.logger.error(`Failed to fetch user from FusionAuth: ${error.message}`);
      throw new Error('Failed to fetch user details');
    }
  }

  /**
   * Get user by ID using API key
   */
  async getUserById(userId: string): Promise<any> {
    try {
      const url = `${this.fusionAuthUrl}/api/user/${userId}`;
      
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: {
            'Authorization': this.apiKey,
            // 'X-FusionAuth-TenantId': this.tenantId,
          },
        }),
      );

      this.logger.log(`User fetched by ID: ${userId}`);
      return response.data.user;
    } catch (error) {
      this.logger.error(`Failed to fetch user by ID: ${error.message}`);
      throw new Error('Failed to fetch user details');
    }
  }

  /**
   * Search for users in the tenant
   */
  async searchUsers(queryString: string = '*', numberOfResults: number = 100, startRow: number = 0): Promise<any> {
    try {
      const url = `${this.fusionAuthUrl}/api/user/search`;
      
      const response = await firstValueFrom(
        this.httpService.post(
          url,
          {
            search: {
              queryString,
              numberOfResults,
              startRow,
              sortFields: [
                {
                  name: 'email',
                  order: 'asc',
                },
              ],
            },
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

      this.logger.log(`Users searched successfully. Total: ${response.data.total}`);
      return response.data;
    } catch (error) {
      this.logger.error(`Failed to search users: ${error.response?.data?.message || error.message}`);
      throw new Error('Failed to search users');
    }
  }

  /**
   * Get tenant details by tenant ID
   */
  async getTenantById(tenantId: string): Promise<any> {
    try {
      const url = `${this.fusionAuthUrl}/api/tenant/${tenantId}`;
      
      const response = await firstValueFrom(
        this.httpService.get(url, {
          headers: {
            'Authorization': this.apiKey,
          },
        }),
      );

      this.logger.log(`Tenant details fetched: ${tenantId}`);
      return response.data.tenant;
    } catch (error) {
      this.logger.error(`Failed to fetch tenant details: ${error.response?.data?.message || error.message}`);
      throw new Error('Failed to fetch tenant details');
    }
  }

  /**
   * Get current tenant details (using configured tenant ID)
   */
  async getCurrentTenant(): Promise<any> {
    return this.getTenantById(this.tenantId);
  }

  /**
   * Generate Google OAuth login URL via FusionAuth
   * Uses direct IdP initiation to bypass FusionAuth login page
   */
  async getGoogleLoginUrl(redirectUri: string): Promise<string> {
    // Get Google Identity Provider ID from config
    const googleIdpId = this.configService.get<string>('GOOGLE_IDP_ID') || '1af47fbc-5156-43c8-89ce-3b5474d55f08';
    
    const params = new URLSearchParams();
    params.append('client_id', this.applicationId);
    params.append('redirect_uri', redirectUri);
    params.append('response_type', 'code');
    params.append('scope', 'openid email profile');
    params.append('idp', googleIdpId); // Direct IdP initiation - goes straight to Google
    params.append('tenantId', this.tenantId);

    return `${this.fusionAuthUrl}/oauth2/authorize?${params.toString()}`;
  }

  /**
   * Exchange OAuth code for tokens via FusionAuth
   */
  async exchangeOAuthCode(code: string, redirectUri: string): Promise<any> {
    try {
      const url = `${this.fusionAuthUrl}/oauth2/token`;
      
      const response = await firstValueFrom(
        this.httpService.post(
          url,
          new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: redirectUri,
            client_id: this.applicationId,
            client_secret: this.apiKey,
          }).toString(),
          {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
            },
          },
        ),
      );

      this.logger.log('OAuth code exchanged successfully');
      return response.data;
    } catch (error) {
      this.logger.error(`OAuth code exchange failed: ${error.response?.data?.message || error.message}`);
      throw new Error('OAuth authentication failed');
    }
  }

  /**
   * Link Google identity to existing FusionAuth user
   */
  async linkGoogleIdentity(userId: string, googleUserId: string, identityProviderId: string): Promise<void> {
    try {
      const url = `${this.fusionAuthUrl}/api/identity-provider/link`;
      
      await firstValueFrom(
        this.httpService.post(
          url,
          {
            identityProviderLink: {
              identityProviderId,
              identityProviderUserId: googleUserId,
              userId,
            },
          },
          {
            headers: {
              'Authorization': this.apiKey,
              'Content-Type': 'application/json',
            },
          },
        ),
      );

      this.logger.log(`Linked Google identity for user: ${userId}`);
    } catch (error) {
      this.logger.error(`Failed to link Google identity: ${error.message}`);
      throw new Error('Failed to link Google identity');
    }
  }

  /**
   * Find user by email in the tenant
   * Returns user if found, null otherwise
   */
  async findUserByEmail(email: string): Promise<any> {
    try {
      const result = await this.searchUsers(`email:${email}`, 1);
      
      if (result.users && result.users.length > 0) {
        this.logger.log(`User found by email: ${email}`);
        return result.users[0];
      }
      
      this.logger.log(`User not found by email: ${email}`);
      return null;
    } catch (error) {
      this.logger.error(`Failed to find user by email: ${error.message}`);
      throw new Error('Failed to find user');
    }
  }

  /**
   * Generate JWT for existing user (for OAuth flows)
   * This uses FusionAuth's login API with the user's ID
   */
  async generateJWTForUser(userId: string): Promise<FusionAuthLoginResponse> {
    try {
      const url = `${this.fusionAuthUrl}/api/jwt/issue`;
      
      const response = await firstValueFrom(
        this.httpService.post(
          url,
          {
            applicationId: this.applicationId,
            userId: userId,
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

      this.logger.log(`JWT generated for user: ${userId}`);
      return {
        token: response.data.token,
        refreshToken: response.data.refreshToken || '',
        user: {
          id: userId,
          email: '',
        },
      };
    } catch (error) {
      this.logger.error(`Failed to generate JWT: ${error.response?.data?.message || error.message}`);
      throw new Error('Failed to generate JWT');
    }
  }
}
