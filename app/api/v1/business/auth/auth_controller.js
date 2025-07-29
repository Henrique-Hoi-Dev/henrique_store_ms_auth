const AuthService = require('./auth_service');
const HttpStatus = require('http-status');
const BaseController = require('../../base/base_controller');
const { AuditLogger } = require('../../../../utils/audit_logger');

class AuthController extends BaseController {
    constructor() {
        super();
        this._authService = new AuthService();
    }

    async generateTokens(req, res, next) {
        try {
            const data = await this._authService.generateTokens(req.body);
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

    async verifyToken(req, res, next) {
        try {
            const data = await this._authService.verifyToken(req.headers.authorization);
            res.status(HttpStatus.status.OK).json(this.parseKeysToCamelcase({ data }));
        } catch (err) {
            next(this.handleError(err));
        }
    }

    async logout(req, res, next) {
        try {
            const data = await this._authService.logout(req.body);
            res.status(HttpStatus.status.OK).json(
                this.parseKeysToCamelcase({
                    data
                })
            );
        } catch (err) {
            next(this.handleError(err));
        }
    }

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
                    message: 'Password recovery email sent'
                })
            );
        } catch (err) {
            next(this.handleError(err));
        }
    }

    async verifyResetToken(req, res, next) {
        try {
            const data = await this._authService.verifyResetToken(req.body.token);

            res.status(HttpStatus.status.OK).json(this.parseKeysToCamelcase({ data }));
        } catch (err) {
            next(this.handleError(err));
        }
    }

    async confirmPasswordReset(req, res, next) {
        try {
            await this._authService.confirmPasswordReset(req.body.token, req.body.userId);

            res.status(HttpStatus.status.OK).json(
                this.parseKeysToCamelcase({
                    message: 'Password reset confirmed'
                })
            );
        } catch (err) {
            next(this.handleError(err));
        }
    }

    async verifyEmailToken(req, res, next) {
        try {
            const data = await this._authService.verifyEmailToken(req.body.token);

            res.status(HttpStatus.status.OK).json(this.parseKeysToCamelcase({ data }));
        } catch (err) {
            next(this.handleError(err));
        }
    }

    async resendVerification(req, res, next) {
        try {
            await this._authService.resendVerification(req.body);

            res.status(HttpStatus.status.OK).json(
                this.parseKeysToCamelcase({
                    message: 'Verification email resent'
                })
            );
        } catch (err) {
            next(this.handleError(err));
        }
    }

    async cleanupExpiredTokens(req, res, next) {
        try {
            const result = await this._authService.cleanupExpiredTokens();

            res.status(HttpStatus.status.OK).json(
                this.parseKeysToCamelcase({
                    message: 'Expired tokens cleanup completed',
                    cleanedCount: result.cleanedCount
                })
            );
        } catch (err) {
            next(this.handleError(err));
        }
    }
}

module.exports = AuthController;
