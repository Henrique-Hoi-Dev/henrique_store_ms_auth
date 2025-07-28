# Microserviço de Autenticação - Auth MS

Este é o microserviço responsável por toda a lógica de autenticação e autorização da plataforma e-commerce Henrique
Store.

## 🎯 Funcionalidades

### Autenticação

- ✅ Login com email/senha
- ✅ Registro de usuários
- ✅ Autenticação Google OAuth2
- ✅ Refresh token automático
- ✅ Logout com invalidação de tokens
- ✅ Verificação de tokens

### Segurança

- ✅ Hash de senhas com bcrypt
- ✅ JWT tokens (access + refresh)
- ✅ Blacklist de tokens revogados
- ✅ Rate limiting contra ataques
- ✅ Autenticação de dois fatores (2FA)
- ✅ Validação rigorosa de inputs
- ✅ Audit logging completo

### Autorização

- ✅ Roles: BUYER, SELLER, ADMIN
- ✅ Middleware de verificação de token
- ✅ Middleware de roles
- ✅ Verificação de email

## 🚀 Início Rápido

### Pré-requisitos

- Node.js >= 18.20.0
- PostgreSQL
- Redis (opcional, para cache)

### Instalação

1. **Clone e instale dependências:**

```bash
cd henrique_store_ms_auth
npm install
```

2. **Configure as variáveis de ambiente:**

```bash
cp env.sample .env
```

3. **Configure o .env:**

```env
NODE_ENV=development
PORT_SERVER=3000
DB_HOST=localhost
DB_PORT=5432
DB_NAME=henrique_store
DB_USER=postgres
DB_PASS=postgres
DB_DIALECT=postgres

# JWT
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d

# Google OAuth2
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

4. **Execute as migrations:**

```bash
npm run migrate
```

5. **Execute os seeders:**

```bash
npm run seed
```

6. **Inicie o servidor:**

```bash
npm run dev
```

## 📡 APIs Disponíveis

### Base URL: `http://localhost:3000/v1/auth`

| Método | Endpoint               | Descrição                 |
| ------ | ---------------------- | ------------------------- |
| POST   | `/register`            | Registro de usuário       |
| POST   | `/login`               | Login com email/senha     |
| POST   | `/google`              | Login com Google OAuth2   |
| POST   | `/refresh`             | Renovar access token      |
| POST   | `/logout`              | Logout e invalidar tokens |
| GET    | `/verify-token`        | Verificar token           |
| POST   | `/complete-2fa`        | Completar login 2FA       |
| POST   | `/google/complete-2fa` | Completar Google 2FA      |

## 🔧 Estrutura do Projeto

```
henrique_store_ms_auth/
├── app/
│   ├── api/v1/business/
│   │   ├── auth/                 # Módulo de autenticação
│   │   │   ├── auth_controller.js
│   │   │   ├── auth_service.js
│   │   │   ├── auth_router.js
│   │   │   └── auth_validation.js
│   │   └── user/                 # Módulo de usuários (existente)
│   ├── main/
│   │   ├── app.js
│   │   ├── bootstrap.js
│   │   ├── routers.js
│   │   └── verify_token_middleware.js
│   └── utils/
├── config/
├── migrations/
├── models/
├── seeders/
└── tests/
```

## 🔐 Segurança

### Tokens JWT

- **Access Token**: 24 horas
- **Refresh Token**: 7 dias
- **Temp Token (2FA)**: 5 minutos

### Blacklist de Tokens

- Tokens revogados são armazenados no banco
- Limpeza automática de tokens expirados
- Job agendado para limpeza a cada hora

### Rate Limiting

- Proteção contra ataques de força bruta
- Bloqueio temporário após 5 tentativas falhadas
- Duração do bloqueio: 15 minutos

### 2FA (Autenticação de Dois Fatores)

- TOTP (Time-based One-Time Password)
- Códigos de backup
- QR Code para configuração

## 🔄 Integração com Outros Microserviços

### Verificação de Token via HTTP

```bash
GET /v1/auth/verify-token
Authorization: Bearer <token>
```

### Verificação Programática

```javascript
const { verifyTokenProgrammatically } = require('./verify_token_middleware');

const userInfo = await verifyTokenProgrammatically(token);
```

### Middleware para Outros Microserviços

```javascript
const { verifyToken, requireRole } = require('./verify_token_middleware');

// Verificar token
app.use('/protected', verifyToken);

// Verificar role específica
app.use('/admin', verifyToken, requireRole('ADMIN'));
```

## 🧪 Testes

### Executar todos os testes:

```bash
npm test
```

### Executar testes unitários:

```bash
npm run test:unit
```

### Executar testes de integração:

```bash
npm run test:integration
```

### Executar com coverage:

```bash
npm run coverage
```

## 📊 Monitoramento

### Health Check

```
GET /v1/health
```

### Logs

- Todas as tentativas de login (sucesso/falha)
- Registro de usuários
- Logouts
- Refresh de tokens
- Verificações de token

### Métricas

- Tokens na blacklist
- Tokens expirados limpos
- Tentativas de login por hora
- Usuários ativos

## 🐳 Docker

### Build da imagem:

```bash
docker build -t auth-ms .
```

### Executar com Docker Compose:

```bash
docker-compose up -d
```

## 📝 Scripts Disponíveis

| Script             | Descrição                      |
| ------------------ | ------------------------------ |
| `npm run dev`      | Inicia em modo desenvolvimento |
| `npm start`        | Inicia em modo produção        |
| `npm test`         | Executa todos os testes        |
| `npm run migrate`  | Executa migrations             |
| `npm run seed`     | Executa seeders                |
| `npm run lint`     | Executa linting                |
| `npm run coverage` | Executa testes com coverage    |

## 🔧 Configuração Avançada

### Variáveis de Ambiente

| Variável                 | Descrição                   | Padrão        |
| ------------------------ | --------------------------- | ------------- |
| `NODE_ENV`               | Ambiente de execução        | `development` |
| `PORT_SERVER`            | Porta do servidor           | `3000`        |
| `JWT_SECRET`             | Chave secreta JWT           | -             |
| `JWT_REFRESH_SECRET`     | Chave secreta refresh       | -             |
| `JWT_EXPIRES_IN`         | Expiração access token      | `24h`         |
| `JWT_REFRESH_EXPIRES_IN` | Expiração refresh token     | `7d`          |
| `GOOGLE_CLIENT_ID`       | Google OAuth2 Client ID     | -             |
| `GOOGLE_CLIENT_SECRET`   | Google OAuth2 Client Secret | -             |

### Configuração de Banco

| Variável     | Descrição        | Padrão           |
| ------------ | ---------------- | ---------------- |
| `DB_HOST`    | Host do banco    | `localhost`      |
| `DB_PORT`    | Porta do banco   | `5432`           |
| `DB_NAME`    | Nome do banco    | `henrique_store` |
| `DB_USER`    | Usuário do banco | `postgres`       |
| `DB_PASS`    | Senha do banco   | `postgres`       |
| `DB_DIALECT` | Dialeto do banco | `postgres`       |

## 🤝 Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## 📞 Suporte

Para suporte, envie um email para suporte@henrique-store.com ou abra uma issue no repositório.
