const jwt = require('jsonwebtoken');
const BaseService = require('../../base/base_service');
const config = require('../../../../../config/config');
const logger = require('../../../../utils/logger');
const UserProvider = require('../../../../providers/user_provider');
const AuthModelBlacklist = require('./auth_model_blacklist');
const { generateAccessToken, generateRefreshToken, validVerifyToken } = require('../../../../utils/jwt');

class AuthService extends BaseService {
    constructor() {
        super();
        this._userProvider = new UserProvider();
        this._modelBlacklist = AuthModelBlacklist;
    }

    /**
     * Generate Tokens
     */
    async generateTokens(userData) {
        try {
            const { userId, email, role } = userData;

            if (!userId || !email || !role) {
                throw new Error('Missing required user data');
            }

            // Generate tokens
            const accessToken = generateAccessToken({
                userId,
                email,
                role
            });

            const refreshToken = generateRefreshToken({
                userId,
                email
            });

            return {
                accessToken,
                refreshToken,
                expiresIn: config.jwt.accessTokenExpiry
            };
        } catch (error) {
            logger.error('Token generation error:', error);
            throw error;
        }
    }

    /**
     * Verify Token
     */
    async verifyToken(token) {
        try {
            token = token.replace('Bearer ', '');
            if (!token) {
                throw new Error('Token is required');
            }

            const isBlacklisted = await this._modelBlacklist.findOne({
                where: { token }
            });

            if (isBlacklisted) {
                throw new Error('Token is blacklisted');
            }

            // Verify JWT token
            const decoded = validVerifyToken(token);

            return {
                valid: true,
                userId: decoded.userId,
                email: decoded.email,
                role: decoded.role,
                exp: decoded.exp,
                decoded
            };
        } catch (error) {
            logger.error('Token verification error:', error);
            throw new Error('Invalid token');
        }
    }

    /**
     * Logout
     */
    async logout(body) {
        try {
            const { token } = body;

            if (!token) {
                throw new Error('TOKEN_REQUIRED');
            }

            const decoded = validVerifyToken(token);
            // Add token to blacklist
            await this._modelBlacklist.create({
                token,
                type: decoded.type,
                expiresAt: new Date(decoded.exp * 1000)
            });

            return {
                success: true,
                userId: decoded.userId
            };
        } catch (error) {
            logger.error('Logout error:', error);
            throw error;
        }
    }

    /**
     * Forgot Password
     */
    async forgotPassword(userData) {
        try {
            const { email, userId } = userData;

            if (!email || !userId) {
                throw new Error('Email and userId are required');
            }

            // Generate reset token
            const resetToken = jwt.sign({ userId, email, type: 'password_reset' }, config.jwt.secret, {
                expiresIn: '1h'
            });

            // TODO: Send email with reset token
            logger.info(`Password reset token generated for user ${userId}: ${resetToken}`);

            return {
                success: true,
                resetToken
            };
        } catch (error) {
            logger.error('Forgot password error:', error);
            throw error;
        }
    }

    /**
     * Verify Reset Token
     */
    async verifyResetToken(token) {
        try {
            if (!token) {
                throw new Error('Reset token is required');
            }

            const decoded = jwt.verify(token, config.jwt.secret);

            if (decoded.type !== 'password_reset') {
                throw new Error('Invalid token type');
            }

            return {
                valid: true,
                userId: decoded.userId,
                email: decoded.email
            };
        } catch (error) {
            logger.error('Reset token verification error:', error);
            throw new Error('Invalid or expired reset token');
        }
    }

    /**
     * Confirm Password Reset
     */
    async confirmPasswordReset(token, userId) {
        try {
            if (!token || !userId) {
                throw new Error('Token and userId are required');
            }

            const decoded = jwt.verify(token, config.jwt.secret);

            if (decoded.type !== 'password_reset' || decoded.userId !== userId) {
                throw new Error('Invalid reset token');
            }

            // TODO: Update user password
            logger.info(`Password reset confirmed for user ${userId}`);

            return {
                success: true,
                userId: decoded.userId
            };
        } catch (error) {
            logger.error('Password reset confirmation error:', error);
            throw new Error('Password reset confirmation failed');
        }
    }

    /**
     * Verify Email Token
     */
    async verifyEmailToken(token) {
        try {
            if (!token) {
                throw new Error('Email verification token is required');
            }

            const decoded = jwt.verify(token, config.jwt.secret);

            if (decoded.type !== 'email_verification') {
                throw new Error('Invalid token type');
            }

            return {
                valid: true,
                userId: decoded.userId,
                email: decoded.email
            };
        } catch (error) {
            logger.error('Email token verification error:', error);
            throw new Error('Invalid or expired email verification token');
        }
    }

    /**
     * Resend Verification
     */
    async resendVerification(userData) {
        try {
            const { email, userId } = userData;

            if (!email || !userId) {
                throw new Error('Email and userId are required');
            }

            // Generate verification token
            const verificationToken = jwt.sign({ userId, email, type: 'email_verification' }, config.jwt.secret, {
                expiresIn: '24h'
            });

            // TODO: Send email with verification token
            logger.info(`Email verification token generated for user ${userId}: ${verificationToken}`);

            return {
                success: true,
                verificationToken
            };
        } catch (error) {
            logger.error('Resend verification error:', error);
            throw error;
        }
    }

    /**
     * Clean up expired tokens from blacklist
     */
    async cleanupExpiredTokens() {
        try {
            const result = await this._modelBlacklist.destroy({
                where: {
                    expiresAt: {
                        [require('sequelize').Op.lt]: new Date()
                    }
                }
            });

            if (result > 0) {
                logger.info(`🧹 Cleaned up ${result} expired tokens from blacklist`);
            }

            return {
                success: true,
                cleanedCount: result
            };
        } catch (error) {
            logger.error('❌ Error cleaning up expired tokens:', error);
            throw error;
        }
    }

    /**
     * Schedule token cleanup job
     * This method should be called during application startup
     */
    scheduleTokenCleanup() {
        const schedule = require('node-schedule');

        // Run cleanup every hour
        schedule.scheduleJob('0 * * * *', async () => {
            try {
                await this.cleanupExpiredTokens();
            } catch (error) {
                logger.error('❌ Scheduled token cleanup failed:', error);
            }
        });

        // Also run cleanup on startup
        this.cleanupExpiredTokens().catch((error) => {
            logger.error('❌ Initial token cleanup failed:', error);
        });

        logger.info('⏰ Token cleanup job scheduled');
    }
}

module.exports = AuthService;
