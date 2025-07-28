const AuthService = require('./auth_service');
const HttpStatus = require('http-status');
const BaseController = require('../../base/base_controller');
const { AuditLogger } = require('../../../../utils/audit_logger');

class AuthController extends BaseController {
    constructor() {
        super();
        this._authService = new AuthService();
    }

    /**
     * User Login
     * POST /auth/login
     */
    async login(req, res, next) {
        try {
            const { email, password } = req.body;
            const data = await this._authService.login(email, password);

            // Audit log successful login
            AuditLogger.logLogin(
                {
                    id: data.userId,
                    email: email
                },
                AuditLogger.getClientIP(req),
                AuditLogger.getUserAgent(req),
                true,
                'email_password'
            );

            res.status(HttpStatus.status.OK).json(this.parseKeysToCamelcase({ data }));
        } catch (err) {
            // Audit log failed login
            AuditLogger.logLogin(
                { email: req.body.email },
                AuditLogger.getClientIP(req),
                AuditLogger.getUserAgent(req),
                false,
                'email_password'
            );
            next(this.handleError(err));
        }
    }

    /**
     * User Registration
     * POST /auth/register
     */
    async register(req, res, next) {
        try {
            const data = await this._authService.register(req.body);

            // Audit log - extract user info from request body
            AuditLogger.logUserCreated(
                {
                    id: data.userId,
                    email: req.body.email,
                    name: req.body.name,
                    role: req.body.role || 'BUYER'
                },
                null, // No creator for self-registration
                AuditLogger.getClientIP(req),
                AuditLogger.getUserAgent(req)
            );

            res.status(HttpStatus.status.CREATED).json(this.parseKeysToCamelcase({ data }));
        } catch (err) {
            next(this.handleError(err));
        }
    }

    /**
     * Google OAuth2 Authentication
     * POST /auth/google
     */
    async authenticateWithGoogle(req, res, next) {
        try {
            const data = await this._authService.authenticateWithGoogle(req.body.code);

            // Audit log successful Google login
            AuditLogger.logLogin(
                {
                    id: data.userId,
                    email: data.email || 'google_oauth2_user'
                },
                AuditLogger.getClientIP(req),
                AuditLogger.getUserAgent(req),
                true,
                'google_oauth2'
            );

            res.status(HttpStatus.status.OK).json(this.parseKeysToCamelcase({ data }));
        } catch (err) {
            // Audit log failed Google login
            AuditLogger.logLogin(
                { email: 'google_oauth2_user' },
                AuditLogger.getClientIP(req),
                AuditLogger.getUserAgent(req),
                false,
                'google_oauth2'
            );
            next(this.handleError(err));
        }
    }

    /**
     * Refresh Token
     * POST /auth/refresh
     */
    async refreshToken(req, res, next) {
        try {
            const { refreshToken } = req.body;
            const data = await this._authService.refreshToken(refreshToken);

            // Audit log successful token refresh
            AuditLogger.logTokenRefresh(
                {
                    id: data.userId,
                    email: data.email
                },
                AuditLogger.getClientIP(req),
                AuditLogger.getUserAgent(req),
                true
            );

            res.status(HttpStatus.status.OK).json(this.parseKeysToCamelcase({ data }));
        } catch (err) {
            // Audit log failed token refresh
            AuditLogger.logTokenRefresh(
                { email: 'unknown' },
                AuditLogger.getClientIP(req),
                AuditLogger.getUserAgent(req),
                false
            );
            next(this.handleError(err));
        }
    }

    /**
     * Logout
     * POST /auth/logout
     */
    async logout(req, res, next) {
        try {
            const { accessToken, refreshToken } = req.body;
            await this._authService.logout(accessToken, refreshToken);

            // Audit log successful logout
            AuditLogger.logLogout(
                {
                    id: req.user?.id,
                    email: req.user?.email
                },
                AuditLogger.getClientIP(req),
                AuditLogger.getUserAgent(req),
                true
            );

            res.status(HttpStatus.status.OK).json(
                this.parseKeysToCamelcase({
                    message: 'Logout realizado com sucesso'
                })
            );
        } catch (err) {
            next(this.handleError(err));
        }
    }

    /**
     * Verify Token
     * GET /auth/verify-token
     */
    async verifyToken(req, res, next) {
        try {
            const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
            const data = await this._authService.verifyToken(token);

            res.status(HttpStatus.status.OK).json(this.parseKeysToCamelcase({ data }));
        } catch (err) {
            next(this.handleError(err));
        }
    }

    /**
     * Complete Login with 2FA
     * POST /auth/complete-2fa
     */
    async completeLoginWith2FA(req, res, next) {
        try {
            const { userId, token, method } = req.body;
            const data = await this._authService.completeLoginWith2FA(userId, token, method);

            // Audit log successful 2FA login
            AuditLogger.logLogin(
                {
                    id: data.userId,
                    email: data.email
                },
                AuditLogger.getClientIP(req),
                AuditLogger.getUserAgent(req),
                true,
                '2fa'
            );

            res.status(HttpStatus.status.OK).json(this.parseKeysToCamelcase({ data }));
        } catch (err) {
            next(this.handleError(err));
        }
    }

    /**
     * Complete Google OAuth2 login with 2FA
     * POST /auth/google/complete-2fa
     */
    async completeGoogleLoginWith2FA(req, res, next) {
        try {
            const data = await this._authService.completeGoogleLoginWith2FA(req.body.userId, req.body);

            // Audit log successful Google login with 2FA
            AuditLogger.logLogin(
                {
                    id: data.userId,
                    email: 'google_oauth2_user'
                },
                AuditLogger.getClientIP(req),
                AuditLogger.getUserAgent(req),
                true,
                'google_oauth2_2fa'
            );

            res.status(HttpStatus.status.OK).json(this.parseKeysToCamelcase({ data }));
        } catch (err) {
            next(this.handleError(err));
        }
    }
}

module.exports = AuthController;
