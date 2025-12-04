import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

export interface JwtPayload {
  sub: string; // User ID
  email: string;
  roles?: string[];
  applicationId?: string;
  iat?: number;
  exp?: number;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        // Extract from Authorization header
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        // Extract from cookie
        (request: Request) => {
          return request?.cookies?.accessToken;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET') || 'default-secret',
      // For production, use FusionAuth public key:
      // secretOrKeyProvider: (request, rawJwtToken, done) => {
      //   // Fetch public key from FusionAuth
      //   const publicKey = configService.get<string>('JWT_PUBLIC_KEY');
      //   done(null, publicKey);
      // },
    });
  }

  async validate(payload: JwtPayload) {
    if (!payload.sub) {
      throw new UnauthorizedException('Invalid token payload');
    }

    // Return user object that will be attached to request
    return {
      userId: payload.sub,
      email: payload.email,
      roles: payload.roles || [],
      applicationId: payload.applicationId,
    };
  }
}
