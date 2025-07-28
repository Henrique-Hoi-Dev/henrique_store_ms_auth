const jwt = require('jsonwebtoken');
const config = require('../../../config/config');

/**
 * Gera um token JWT com payload e opções customizáveis
 * @param {Object} payload - Dados a serem incluídos no token
 * @param {Object} options - Opções de configuração do token
 * @returns {string} Token JWT gerado
 */
const generateToken = ({ payload = {}, options = {} } = {}) => {
    if (!config.jwt.secret) {
        throw new Error('MISSING_JWT_SECRET');
    }

    const tokenOptions = {
        expiresIn: options.expiresIn || config.jwt.accessTokenExpiry,
        issuer: options.issuer || process.env.JWT_ISSUER,
        audience: options.audience || process.env.JWT_AUDIENCE,
        ...options
    };

    const token = jwt.sign(payload, config.jwt.secret, tokenOptions);
    return token;
};

/**
 * Gera um token de acesso para usuário
 * @param {Object} user - Dados do usuário
 * @param {Object} options - Opções adicionais
 * @returns {string} Token de acesso
 */
const generateAccessToken = ({ user, options = {} } = {}) => {
    if (!user || !user.id) {
        throw new Error('USER_DATA_REQUIRED');
    }

    const payload = {
        id: user.id,
        email: user.email,
        role: user.role,
        type: 'access'
    };

    return generateToken({
        payload,
        options: {
            expiresIn: '15m',
            ...options
        }
    });
};

/**
 * Gera um token de refresh para usuário
 * @param {Object} user - Dados do usuário
 * @param {Object} options - Opções adicionais
 * @returns {string} Token de refresh
 */
const generateRefreshToken = ({ user, options = {} } = {}) => {
    if (!user || !user.id) {
        throw new Error('USER_DATA_REQUIRED');
    }

    const payload = {
        id: user.id,
        type: 'refresh'
    };

    // Use refresh secret for refresh tokens
    if (!config.jwt.refreshSecret) {
        throw new Error('MISSING_JWT_REFRESH_SECRET');
    }

    const tokenOptions = {
        expiresIn: options.expiresIn || config.jwt.refreshTokenExpiry,
        issuer: options.issuer || process.env.JWT_ISSUER,
        audience: options.audience || process.env.JWT_AUDIENCE,
        ...options
    };

    const token = jwt.sign(payload, config.jwt.refreshSecret, tokenOptions);
    return token;
};

/**
 * Gera um token de reset de senha
 * @param {Object} user - Dados do usuário
 * @param {Object} options - Opções adicionais
 * @returns {string} Token de reset
 */
const generateResetToken = ({ user, options = {} } = {}) => {
    if (!user || !user.id) {
        throw new Error('USER_DATA_REQUIRED');
    }

    const payload = {
        id: user.id,
        email: user.email,
        type: 'reset'
    };

    return generateToken({
        payload,
        options: {
            expiresIn: '1h',
            ...options
        }
    });
};

/**
 * Gera um token de verificação de email
 * @param {Object} user - Dados do usuário
 * @param {Object} options - Opções adicionais
 * @returns {string} Token de verificação
 */
const generateEmailVerificationToken = ({ user, options = {} } = {}) => {
    if (!user || !user.id) {
        throw new Error('USER_DATA_REQUIRED');
    }

    const payload = {
        id: user.id,
        email: user.email,
        type: 'email_verification'
    };

    return generateToken({
        payload,
        options: {
            expiresIn: '24h',
            ...options
        }
    });
};

module.exports = {
    generateToken,
    generateAccessToken,
    generateRefreshToken,
    generateResetToken,
    generateEmailVerificationToken
};
