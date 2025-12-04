# API Gateway - NestJS

This is the API Gateway for the iCustomer application, built with NestJS and integrated with FusionAuth for authentication.

## Features

- ✅ FusionAuth Integration for Authentication
- ✅ JWT Token Management (Access & Refresh Tokens)
- ✅ Cookie-based Token Storage
- ✅ User Context Forwarding to Microservices
- ✅ CORS Configuration
- ✅ Input Validation
- ✅ Protected Routes with Guards

## Prerequisites

- Node.js (v18 or higher)
- npm or yarn
- FusionAuth instance running (with credentials)

## Installation

```bash
npm install
```

## Configuration

1. Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

2. Update the `.env` file with your FusionAuth credentials:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# FusionAuth Configuration
FUSIONAUTH_URL=http://localhost:9011
FUSIONAUTH_API_KEY=your-fusionauth-api-key
FUSIONAUTH_APPLICATION_ID=your-application-id
FUSIONAUTH_TENANT_ID=your-tenant-id

# JWT Configuration
JWT_SECRET=your-jwt-secret-key
JWT_PUBLIC_KEY=your-fusionauth-public-key

# Microservices URLs
AUDIENCE_SERVICE_URL=http://localhost:3001
JOURNEY_SERVICE_URL=http://localhost:3002

# CORS Configuration
FRONTEND_URL=http://localhost:5173

# Cookie Configuration
COOKIE_SECRET=your-cookie-secret-key
```

## Running the Application

### Development Mode
```bash
npm run start:dev
```

### Production Mode
```bash
npm run build
npm run start:prod
```

The API Gateway will be available at: `http://localhost:3000/api`

## API Endpoints

### Authentication Endpoints

#### Signup
```http
POST /api/auth/signup
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

Response includes JWT tokens and sets httpOnly cookies.

#### Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

#### Logout
```http
POST /api/auth/logout
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

#### Get Current User
```http
GET /api/auth/me
Authorization: Bearer <access-token>
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (React + Vite)                   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ HTTP/HTTPS
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   NestJS API Gateway                         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Auth Module (FusionAuth Integration)                │  │
│  │  - JWT Validation                                     │  │
│  │  - Token Refresh                                      │  │
│  │  - User Context Extraction                           │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Guards & Interceptors                               │  │
│  │  - JWT Auth Guard                                     │  │
│  │  - User Context Interceptor                          │  │
│  └──────────────────────────────────────────────────────┘  │
└────────┬──────────────────────────┬─────────────────────────┘
         │                          │
         │                          │
    ┌────▼─────┐              ┌────▼─────┐
    │ Audience │              │ Journey  │
    │ Service  │              │ Service  │
    └──────────┘              └──────────┘
```

## Project Structure

```
src/
├── auth/                      # Authentication module
│   ├── dto/                   # Data Transfer Objects
│   ├── guards/                # Auth guards
│   ├── auth.controller.ts     # Auth endpoints
│   ├── auth.service.ts        # Auth business logic
│   ├── auth.module.ts         # Auth module definition
│   ├── fusionauth.client.ts   # FusionAuth API client
│   └── jwt.strategy.ts        # JWT validation strategy
├── common/                    # Shared utilities
│   ├── decorators/            # Custom decorators
│   └── interceptors/          # Request/Response interceptors
├── app.module.ts              # Root module
└── main.ts                    # Application entry point
```

## Security Features

1. **JWT Validation**: All protected routes validate JWT tokens
2. **HttpOnly Cookies**: Tokens stored in secure httpOnly cookies
3. **CORS**: Configured to allow only specified origins
4. **Input Validation**: All inputs validated using class-validator
5. **Error Handling**: Sensitive information not exposed in errors

## User Context Forwarding

The API Gateway automatically forwards user context to microservices via headers:

- `x-user-id`: User ID from JWT
- `x-user-email`: User email
- `x-user-roles`: User roles (JSON array)
- `x-tenant-id`: Tenant/Application ID

## Next Steps

1. Create Audience Service microservice
2. Create Journey Service microservice
3. Add service proxy modules to forward requests
4. Implement additional business logic endpoints

## Testing

```bash
# Unit tests
npm run test

# E2E tests
npm run test:e2e

# Test coverage
npm run test:cov
```

## License

Private - iCustomer Application
