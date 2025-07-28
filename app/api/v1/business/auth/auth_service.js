const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { OAuth2Client } = require('google-auth-library');
const { TokenBlacklist } = require('../../../../models');
const { generateAccessToken, generateRefreshToken, verifyToken: verifyJWTToken } = require('../../../../utils/jwt');
const { validateEmail, validatePassword, validateName } = require('../../../../utils/validators');
const { generate2FASecret, verify2FAToken, generateBackupCodes } = require('../../../../utils/2fa-utils');
const { sendWelcomeEmail, sendVerificationEmail } = require('../../../../utils/email');
const config = require('../../../../config/config');
const logger = require('../../../../utils/logger');
const UserProvider = require('../../../../providers/user_provider');

class AuthService {
    constructor() {
        this.googleClient = new OAuth2Client(config.google.clientId, config.google.clientSecret);
        this._userProvider = new UserProvider();
    }

    /**
     * User Login
     */
    async login(email, password) {
        try {
            // Validate inputs
            if (!email || !password) {
                throw new Error('Email e senha são obrigatórios');
            }

            if (!validateEmail(email)) {
                throw new Error('Email inválido');
            }

            // Call user service to validate credentials
            const response = await this._userProvider.validateCredentials(email, password);
            const user = response.user;

            // Check if 2FA is enabled
            if (user.twoFactorEnabled) {
                return {
                    userId: user.id,
                    email: user.email,
                    name: user.name,
                    role: user.role,
                    requires2FA: true,
                    tempToken: this._generateTempToken(user.id)
                };
            }

            // Generate tokens
            const accessToken = generateAccessToken({
                userId: user.id,
                email: user.email,
                role: user.role
            });

            const refreshToken = generateRefreshToken({
                userId: user.id,
                email: user.email
            });

            return {
                userId: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                accessToken,
                refreshToken,
                expiresIn: config.jwt.accessTokenExpiry,
                requires2FA: false
            };
        } catch (error) {
            logger.error('Login error:', error);
            throw error;
        }
    }

    /**
     * User Registration
     */
    async register(userData) {
        try {
            const { email, password, name, role = 'BUYER' } = userData;

            // Validate inputs
            if (!email || !password || !name) {
                throw new Error('Email, senha e nome são obrigatórios');
            }

            if (!validateEmail(email)) {
                throw new Error('Email inválido');
            }

            if (!validatePassword(password)) {
                throw new Error('Senha deve ter pelo menos 8 caracteres, incluindo maiúsculas, minúsculas e números');
            }

            if (!validateName(name)) {
                throw new Error('Nome inválido');
            }

            // Call user service to create user
            const response = await this._userProvider.createUser({
                email: email.toLowerCase(),
                password,
                name,
                role
            });

            const user = response.user;

            // Generate tokens
            const accessToken = generateAccessToken({
                userId: user.id,
                email: user.email,
                role: user.role
            });

            const refreshToken = generateRefreshToken({
                userId: user.id,
                email: user.email
            });

            return {
                userId: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                accessToken,
                refreshToken,
                expiresIn: config.jwt.accessTokenExpiry,
                requires2FA: false,
                message: 'Usuário registrado com sucesso. Verifique seu email para confirmar a conta.'
            };
        } catch (error) {
            logger.error('Registration error:', error);
            throw error;
        }
    }

    /**
     * Google OAuth2 Authentication
     */
    async authenticateWithGoogle(code) {
        try {
            // Exchange code for tokens
            const { tokens } = await this.googleClient.getToken(code);

            // Verify the token
            const ticket = await this.googleClient.verifyIdToken({
                idToken: tokens.id_token,
                audience: config.google.clientId
            });

            const payload = ticket.getPayload();
            const { email, name, picture, sub: googleId } = payload;

            // Call user service to find or create user
            const response = await this._userProvider.handleGoogleAuth({
                email: email.toLowerCase(),
                name,
                googleId,
                picture
            });

            const user = response.user;

            // Check if 2FA is enabled
            if (user.twoFactorEnabled) {
                return {
                    userId: user.id,
                    email: user.email,
                    name: user.name,
                    role: user.role,
                    requires2FA: true,
                    tempToken: this._generateTempToken(user.id)
                };
            }

            // Generate tokens
            const accessToken = generateAccessToken({
                userId: user.id,
                email: user.email,
                role: user.role
            });

            const refreshToken = generateRefreshToken({
                userId: user.id,
                email: user.email
            });

            return {
                userId: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                accessToken,
                refreshToken,
                expiresIn: config.jwt.accessTokenExpiry,
                requires2FA: false
            };
        } catch (error) {
            logger.error('Google OAuth error:', error);
            throw new Error('Falha na autenticação com Google');
        }
    }

    /**
     * Refresh Token
     */
    async refreshToken(refreshToken) {
        try {
            if (!refreshToken) {
                throw new Error('Refresh token é obrigatório');
            }

            // Verify refresh token
            const decoded = verifyJWTToken(refreshToken, config.jwt.refreshSecret);

            // Check if token is blacklisted
            const isBlacklisted = await TokenBlacklist.findOne({
                where: { token: refreshToken }
            });

            if (isBlacklisted) {
                throw new Error('Token inválido');
            }

            // Call user service to get user info
            const response = await this._userProvider.getUserById(decoded.userId);
            const user = response.user;

            if (!user || !user.isActive) {
                throw new Error('Usuário não encontrado ou inativo');
            }

            // Generate new tokens
            const newAccessToken = generateAccessToken({
                userId: user.id,
                email: user.email,
                role: user.role
            });

            const newRefreshToken = generateRefreshToken({
                userId: user.id,
                email: user.email
            });

            // Blacklist old refresh token
            await TokenBlacklist.create({
                token: refreshToken,
                type: 'refresh',
                expiresAt: new Date(decoded.exp * 1000)
            });

            return {
                userId: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                accessToken: newAccessToken,
                refreshToken: newRefreshToken,
                expiresIn: config.jwt.accessTokenExpiry
            };
        } catch (error) {
            logger.error('Token refresh error:', error);
            throw error;
        }
    }

    /**
     * Logout
     */
    async logout(accessToken, refreshToken) {
        try {
            // Blacklist access token
            if (accessToken) {
                const decoded = verifyJWTToken(accessToken, config.jwt.secret);
                await TokenBlacklist.create({
                    token: accessToken,
                    type: 'access',
                    expiresAt: new Date(decoded.exp * 1000)
                });
            }

            // Blacklist refresh token
            if (refreshToken) {
                const decoded = verifyJWTToken(refreshToken, config.jwt.refreshSecret);
                await TokenBlacklist.create({
                    token: refreshToken,
                    type: 'refresh',
                    expiresAt: new Date(decoded.exp * 1000)
                });
            }

            return { message: 'Logout realizado com sucesso' };
        } catch (error) {
            logger.error('Logout error:', error);
            throw error;
        }
    }

    /**
     * Verify Token
     */
    async verifyToken(token) {
        try {
            if (!token) {
                throw new Error('Token é obrigatório');
            }

            // Check if token is blacklisted
            const isBlacklisted = await TokenBlacklist.findOne({
                where: { token }
            });

            if (isBlacklisted) {
                throw new Error('Token inválido');
            }

            // Verify token
            const decoded = verifyJWTToken(token, config.jwt.secret);

            // Call user service to get user info
            const response = await this._userProvider.getUserById(decoded.userId);
            const user = response.user;

            if (!user || !user.isActive) {
                throw new Error('Usuário não encontrado ou inativo');
            }

            return {
                userId: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                isEmailVerified: user.isEmailVerified,
                isValid: true
            };
        } catch (error) {
            logger.error('Token verification error:', error);
            throw error;
        }
    }

    /**
     * Complete Login with 2FA
     */
    async completeLoginWith2FA(userId, token, method) {
        try {
            // Call user service to get user 2FA info
            const response = await this._userProvider.getUser2FAInfo(userId);
            const user = response.user;

            if (!user) {
                throw new Error('Usuário não encontrado');
            }

            // Verify 2FA token
            const isValid = await verify2FAToken(token, user.twoFactorSecret, method, user.backupCodes);

            if (!isValid) {
                throw new Error('Código 2FA inválido');
            }

            // Generate tokens
            const accessToken = generateAccessToken({
                userId: user.id,
                email: user.email,
                role: user.role
            });

            const refreshToken = generateRefreshToken({
                userId: user.id,
                email: user.email
            });

            return {
                userId: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                accessToken,
                refreshToken,
                expiresIn: config.jwt.accessTokenExpiry,
                requires2FA: false
            };
        } catch (error) {
            logger.error('2FA completion error:', error);
            throw error;
        }
    }

    /**
     * Complete Google OAuth2 login with 2FA
     */
    async completeGoogleLoginWith2FA(userId, data) {
        try {
            const { token, method } = data;
            return await this.completeLoginWith2FA(userId, token, method);
        } catch (error) {
            logger.error('Google 2FA completion error:', error);
            throw error;
        }
    }

    /**
     * Generate temporary token for 2FA
     */
    _generateTempToken(userId) {
        return jwt.sign({ userId, type: 'temp' }, config.jwt.secret, { expiresIn: '5m' });
    }
}

module.exports = AuthService;
