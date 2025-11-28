# Cloud-Native Authentication System

AWS Cognito User Pools의 대안으로 설계된 자체 호스팅 인증 시스템입니다.

## 기능

- 이메일/패스워드 기반 회원가입 및 로그인
- JWT 기반 Access Token, ID Token, Refresh Token 발급
- Refresh Token Rotation을 통한 보안 강화
- Rate Limiting (Redis 기반 Sliding Window)
- 이메일 인증
- 비밀번호 재설정
- 계정 잠금 (무차별 대입 공격 방어)

## 기술 스택

- **Runtime**: Node.js 20
- **Language**: TypeScript
- **Framework**: Express.js
- **Database**: PostgreSQL + Prisma ORM
- **Cache**: Redis (ioredis)
- **Authentication**: JWT (RS256)
- **Validation**: Zod
- **Logging**: Pino

## 시작하기

### 1. 사전 요구사항

- Node.js 20+
- Docker & Docker Compose
- PostgreSQL 16+
- Redis 7+

### 2. RSA 키 생성

JWT 서명을 위한 RSA 키 페어를 생성합니다:

```bash
# 개인 키 생성
openssl genrsa -out private.pem 2048

# 공개 키 추출
openssl rsa -in private.pem -pubout -out public.pem

# 환경 변수용 형식으로 변환 (줄바꿈을 \n으로)
cat private.pem | tr '\n' '~' | sed 's/~/\\n/g'
cat public.pem | tr '\n' '~' | sed 's/~/\\n/g'
```

### 3. 환경 변수 설정

```bash
cp .env.example .env
# .env 파일을 편집하여 JWT_PRIVATE_KEY, JWT_PUBLIC_KEY 등을 설정
```

### 4. Docker Compose로 실행

```bash
# 데이터베이스와 Redis 시작
docker-compose up -d db redis

# 데이터베이스 마이그레이션
npm install
npm run db:push

# 애플리케이션 실행 (개발 모드)
npm run dev

# 또는 전체 스택 실행
docker-compose up -d
```

### 5. API 테스트

```bash
# 회원가입
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecureP@ss123!",
    "profile": {
      "givenName": "John",
      "familyName": "Doe"
    }
  }'

# 이메일 인증 (반환된 verificationToken 사용)
curl -X POST http://localhost:3000/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_VERIFICATION_TOKEN"}'

# 로그인
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecureP@ss123!"
  }'

# 토큰 갱신
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "YOUR_REFRESH_TOKEN"}'

# 현재 사용자 조회
curl http://localhost:3000/users/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# 로그아웃
curl -X POST http://localhost:3000/auth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "YOUR_REFRESH_TOKEN"}'
```

## API 엔드포인트

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | /auth/signup | 회원가입 | No |
| POST | /auth/login | 로그인 | No |
| POST | /auth/logout | 로그아웃 | Yes |
| POST | /auth/refresh | 토큰 갱신 | No |
| POST | /auth/verify-email | 이메일 인증 | No |
| POST | /auth/forgot-password | 비밀번호 재설정 요청 | No |
| POST | /auth/reset-password | 비밀번호 재설정 | No |
| GET | /users/me | 현재 사용자 조회 | Yes |
| GET | /health | 헬스 체크 | No |

## 프로젝트 구조

```
auth-system-code/
├── src/
│   ├── config/           # 설정 파일
│   │   ├── index.ts      # 환경 변수 로드
│   │   ├── database.ts   # Prisma 클라이언트
│   │   ├── redis.ts      # Redis 클라이언트
│   │   └── logger.ts     # Pino 로거
│   ├── controllers/      # API 컨트롤러
│   │   └── auth.ts
│   ├── services/         # 비즈니스 로직
│   │   ├── auth.ts
│   │   ├── rateLimit.ts
│   │   └── tokenBlacklist.ts
│   ├── middlewares/      # Express 미들웨어
│   │   ├── auth.ts
│   │   └── errorHandler.ts
│   ├── utils/            # 유틸리티 함수
│   │   ├── jwt.ts
│   │   ├── password.ts
│   │   ├── tokens.ts
│   │   └── response.ts
│   └── index.ts          # 애플리케이션 진입점
├── prisma/
│   └── schema.prisma     # 데이터베이스 스키마
├── Dockerfile
├── docker-compose.yml
├── package.json
├── tsconfig.json
└── .env.example
```

## 프로덕션 배포

### AWS ECS Fargate 배포

1. ECR에 Docker 이미지 푸시
2. ECS Task Definition 생성
3. ECS Service 생성 (ALB 연결)
4. RDS PostgreSQL 인스턴스 생성
5. ElastiCache Redis 클러스터 생성
6. Secrets Manager에 민감 정보 저장

자세한 배포 가이드는 논문의 제3장을 참조하세요.

## 라이선스

MIT
