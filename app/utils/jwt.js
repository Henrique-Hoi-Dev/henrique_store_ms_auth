const jwt = require('jsonwebtoken');
const config = require('../../config/config');

// Token Generators
const generateToken = (payload = {}) => {
    if (!config.jwt.secret) {
        throw new Error('MISSING_JWT_SECRET');
    }

    const tokenOptions = {
        expiresIn: config.jwt.accessTokenExpiry || '24h'
    };

    if (config.jwt.issuer) {
        tokenOptions.issuer = config.jwt.issuer;
    }

    if (config.jwt.audience) {
        tokenOptions.audience = config.jwt.audience;
    }

    const token = jwt.sign(payload, config.jwt.secret, tokenOptions);
    return token;
};

const generateAccessToken = (payload = {}) => {
    return generateToken({
        ...payload,
        type: 'access'
    });
};

const generateRefreshToken = (payload = {}) => {
    return generateToken({
        ...payload,
        type: 'refresh'
    });
};

const generateResetToken = (payload = {}) => {
    return generateToken({
        ...payload,
        type: 'password_reset'
    });
};

const generateEmailVerificationToken = (payload = {}) => {
    return generateToken({
        ...payload,
        type: 'email_verification'
    });
};

// Token Validators
const validVerifyToken = (token = '') => {
    if (!token) {
        throw new Error('TOKEN_REQUIRED');
    }

    if (!config.jwt.secret) {
        throw new Error('MISSING_JWT_SECRET');
    }

    try {
        const verifyOptions = {};

        if (config.jwt.issuer) {
            verifyOptions.issuer = config.jwt.issuer;
        }

        if (config.jwt.audience) {
            verifyOptions.audience = config.jwt.audience;
        }

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

const isTokenExpired = (token = '') => {
    try {
        const decoded = jwt.decode(token);
        if (!decoded || !decoded.exp) {
            return true;
        }

        const currentTime = Math.floor(Date.now() / 1000);
        return decoded.exp < currentTime;
    } catch (error) {
        return true;
    }
};

const isTokenType = (token, type) => {
    try {
        const decoded = jwt.decode(token);
        return decoded?.type === type;
    } catch (error) {
        return false;
    }
};

const getUserFromToken = (token) => {
    try {
        const decoded = jwt.decode(token);
        return {
            userId: decoded?.userId,
            email: decoded?.email,
            role: decoded?.role
        };
    } catch (error) {
        return null;
    }
};

// Token Utils
const extractTokenFromHeader = (authHeader) => {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }
    return authHeader.replace('Bearer ', '');
};

const formatAuthHeader = (token) => {
    return `Bearer ${token}`;
};

const isValidTokenFormat = (token) => {
    return token && typeof token === 'string' && token.length > 0;
};

const extractPayload = (token) => {
    try {
        return jwt.decode(token);
    } catch (error) {
        return null;
    }
};

const getTokenExpiration = (token) => {
    try {
        const decoded = jwt.decode(token);
        return decoded?.exp ? new Date(decoded.exp * 1000) : null;
    } catch (error) {
        return null;
    }
};

const getTokenTimeRemaining = (token) => {
    try {
        const decoded = jwt.decode(token);
        if (!decoded?.exp) return 0;

        const currentTime = Math.floor(Date.now() / 1000);
        return Math.max(0, decoded.exp - currentTime);
    } catch (error) {
        return 0;
    }
};

const isTokenNearExpiration = (token, thresholdMinutes = 5) => {
    const timeRemaining = getTokenTimeRemaining(token);
    return timeRemaining > 0 && timeRemaining <= thresholdMinutes * 60;
};

// Hash functions
const hashToken = (token) => {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(token).digest('hex');
};

const verifyTokenHash = (token, hash) => {
    return hashToken(token) === hash;
};

module.exports = {
    // Token Generators
    generateToken,
    generateAccessToken,
    generateRefreshToken,
    generateResetToken,
    generateEmailVerificationToken,

    // Token Validators
    validVerifyToken,
    isTokenExpired,
    isTokenType,
    getUserFromToken,

    // Token Utils
    extractTokenFromHeader,
    formatAuthHeader,
    isValidTokenFormat,
    extractPayload,
    getTokenExpiration,
    getTokenTimeRemaining,
    isTokenNearExpiration,

    // Hash functions
    hashToken,
    verifyTokenHash
};
