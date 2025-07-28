const jwt = require('jsonwebtoken');
const config = require('../../../config/config');

/**
 * Verifica e valida um token JWT
 * @param {string} token - Token JWT a ser verificado
 * @param {Object} options - Opções de verificação
 * @returns {Object} Payload decodificado do token
 */
const validVerifyToken = ({ token = '', options = {} } = {}) => {
    if (!token) {
        throw new Error('TOKEN_REQUIRED');
    }

    if (!config.jwt.secret) {
        throw new Error('MISSING_JWT_SECRET');
    }

    const verifyOptions = {
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE,
        ...options
    };

    try {
        const decoded = jwt.verify(token, config.jwt.secret, verifyOptions);
        return decoded;
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            throw new Error('TOKEN_EXPIRED');
        } else if (error instanceof jwt.JsonWebTokenError) {
            throw new Error('INVALID_TOKEN_SIGNATURE');
        } else if (error instanceof jwt.NotBeforeError) {
            throw new Error('TOKEN_NOT_ACTIVE');
        } else {
            throw new Error('INVALID_TOKEN');
        }
    }
};

/**
 * Decodifica um token JWT sem verificar a assinatura
 * @param {string} token - Token JWT a ser decodificado
 * @returns {Object|null} Payload decodificado ou null se inválido
 */
const decodeToken = ({ token = '' } = {}) => {
    if (!token) {
        return null;
    }

    try {
        return jwt.decode(token);
    } catch (error) {
        return null;
    }
};

/**
 * Verifica se um token JWT está expirado
 * @param {string} token - Token JWT a ser verificado
 * @returns {boolean} true se expirado, false caso contrário
 */
const isTokenExpired = ({ token = '' } = {}) => {
    try {
        const decoded = decodeToken({ token });
        if (!decoded || !decoded.exp) {
            return true;
        }

        const currentTime = Math.floor(Date.now() / 1000);
        return decoded.exp < currentTime;
    } catch (error) {
        return true;
    }
};

/**
 * Verifica se um token é do tipo especificado
 * @param {string} token - Token JWT
 * @param {string} type - Tipo esperado (access, refresh, reset, email_verification)
 * @returns {boolean} true se for do tipo correto
 */
const isTokenType = ({ token = '', type = '' } = {}) => {
    try {
        const decoded = validVerifyToken({ token });
        return decoded && decoded.type === type;
    } catch (error) {
        return false;
    }
};

/**
 * Obtém informações do usuário do token
 * @param {string} token - Token JWT
 * @returns {Object|null} Dados do usuário ou null
 */
const getUserFromToken = ({ token = '' } = {}) => {
    try {
        const decoded = validVerifyToken({ token });
        return {
            id: decoded.id,
            email: decoded.email,
            role: decoded.role,
            type: decoded.type
        };
    } catch (error) {
        return null;
    }
};

/**
 * Verifica e valida um refresh token JWT
 * @param {string} token - Refresh token JWT a ser verificado
 * @param {Object} options - Opções de verificação
 * @returns {Object} Payload decodificado do token
 */
const verifyRefreshToken = ({ token = '', options = {} } = {}) => {
    if (!token) {
        throw new Error('TOKEN_REQUIRED');
    }

    if (!config.jwt.refreshSecret) {
        throw new Error('MISSING_JWT_REFRESH_SECRET');
    }

    const verifyOptions = {
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE,
        ...options
    };

    try {
        const decoded = jwt.verify(token, config.jwt.refreshSecret, verifyOptions);
        return decoded;
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            throw new Error('TOKEN_EXPIRED');
        } else if (error instanceof jwt.JsonWebTokenError) {
            throw new Error('INVALID_TOKEN_SIGNATURE');
        } else if (error instanceof jwt.NotBeforeError) {
            throw new Error('TOKEN_NOT_ACTIVE');
        } else {
            throw new Error('INVALID_TOKEN');
        }
    }
};

module.exports = {
    validVerifyToken,
    verifyRefreshToken,
    decodeToken,
    isTokenExpired,
    isTokenType,
    getUserFromToken
};
