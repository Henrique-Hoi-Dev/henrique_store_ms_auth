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
     * Generate Tokens
     * POST /auth/generate-tokens
     */
    async generateTokens(req, res, next) {
        try {
            const data = await this._authService.generateTokens(req.body);

            // Audit log successful token generation
            AuditLogger.logTokenGeneration(
                {
                    id: req.body.userId,
                    email: req.body.email
                },
                AuditLogger.getClientIP(req),
                AuditLogger.getUserAgent(req),
                true
            );

            res.status(HttpStatus.status.OK).json(this.parseKeysToCamelcase({ data }));
        } catch (err) {
            // Audit log failed token generation
            AuditLogger.logTokenGeneration(
                {
                    id: req.body.userId,
                    email: req.body.email
                },
                AuditLogger.getClientIP(req),
                AuditLogger.getUserAgent(req),
                false
            );
            next(this.handleError(err));
        }
    }

    /**
     * Verify Token
     * POST /auth/verify-token
     */
    async verifyToken(req, res, next) {
        try {
            const data = await this._authService.verifyToken(req.body.token);

            res.status(HttpStatus.status.OK).json(this.parseKeysToCamelcase({ data }));
        } catch (err) {
            next(this.handleError(err));
        }
    }

    /**
     * Logout
     * POST /auth/logout
     */
    async logout(req, res, next) {
        try {
            const { token } = req.body;
            await this._authService.logout(token);

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
     * Forgot Password
     * POST /auth/forgot-password
     */
    async forgotPassword(req, res, next) {
        try {
            await this._authService.forgotPassword(req.body);

            // Audit log password reset request
            AuditLogger.logPasswordReset(
                { email: req.body.email },
                AuditLogger.getClientIP(req),
                AuditLogger.getUserAgent(req)
            );

            res.status(HttpStatus.status.OK).json(
                this.parseKeysToCamelcase({
                    message: 'Email de recuperação enviado'
                })
            );
        } catch (err) {
            next(this.handleError(err));
        }
    }

    /**
     * Verify Reset Token
     * POST /auth/verify-reset-token
     */
    async verifyResetToken(req, res, next) {
        try {
            const data = await this._authService.verifyResetToken(req.body.token);

            res.status(HttpStatus.status.OK).json(this.parseKeysToCamelcase({ data }));
        } catch (err) {
            next(this.handleError(err));
        }
    }

    /**
     * Confirm Password Reset
     * POST /auth/confirm-password-reset
     */
    async confirmPasswordReset(req, res, next) {
        try {
            await this._authService.confirmPasswordReset(req.body.token, req.body.userId);

            res.status(HttpStatus.status.OK).json(
                this.parseKeysToCamelcase({
                    message: 'Reset de senha confirmado'
                })
            );
        } catch (err) {
            next(this.handleError(err));
        }
    }

    /**
     * Verify Email Token
     * POST /auth/verify-email-token
     */
    async verifyEmailToken(req, res, next) {
        try {
            const data = await this._authService.verifyEmailToken(req.body.token);

            res.status(HttpStatus.status.OK).json(this.parseKeysToCamelcase({ data }));
        } catch (err) {
            next(this.handleError(err));
        }
    }

    /**
     * Resend Verification
     * POST /auth/resend-verification
     */
    async resendVerification(req, res, next) {
        try {
            await this._authService.resendVerification(req.body);

            res.status(HttpStatus.status.OK).json(
                this.parseKeysToCamelcase({
                    message: 'Email de verificação reenviado'
                })
            );
        } catch (err) {
            next(this.handleError(err));
        }
    }
}

module.exports = AuthController;
