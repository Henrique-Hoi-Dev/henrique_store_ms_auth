const crypto = require('crypto');

/**
 * Extrai token do header Authorization
 * @param {string} authHeader - Header Authorization
 * @returns {string|null} Token extraído ou null
 */
const extractTokenFromHeader = ({ authHeader = '' } = {}) => {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return null;
    }
    return authHeader.substring(7);
};

/**
 * Formata token para header Authorization
 * @param {string} token - Token JWT
 * @returns {string} Header Authorization formatado
 */
const formatAuthHeader = ({ token = '' } = {}) => {
    if (!token) {
        return '';
    }
    return `Bearer ${token}`;
};

/**
 * Gera hash SHA-256 de um token
 * @param {string} token - Token a ser hasheado
 * @returns {string} Hash do token
 */
const hashToken = ({ token = '' } = {}) => {
    if (!token) {
        return null;
    }
    return crypto.createHash('sha256').update(token).digest('hex');
};

/**
 * Verifica se um token corresponde ao hash
 * @param {string} token - Token a ser verificado
 * @param {string} hash - Hash para comparação
 * @returns {boolean} true se correspondem
 */
const verifyTokenHash = ({ token = '', hash = '' } = {}) => {
    if (!token || !hash) {
        return false;
    }
    const tokenHash = hashToken({ token });
    return tokenHash === hash;
};

/**
 * Calcula data de expiração para token
 * @param {number} hours - Horas até expirar (padrão: 1)
 * @returns {Date} Data de expiração
 */
const calculateTokenExpiration = ({ hours = 1 } = {}) => {
    return new Date(Date.now() + hours * 60 * 60 * 1000);
};

/**
 * Valida formato do token JWT
 * @param {string} token - Token a ser validado
 * @returns {boolean} true se formato válido
 */
const isValidTokenFormat = ({ token = '' } = {}) => {
    if (!token || typeof token !== 'string') {
        return false;
    }

    // Verifica se tem 3 partes separadas por ponto
    const parts = token.split('.');
    return parts.length === 3;
};

/**
 * Extrai payload do token sem verificar assinatura
 * @param {string} token - Token JWT
 * @returns {Object|null} Payload ou null se inválido
 */
const extractPayload = ({ token = '' } = {}) => {
    if (!isValidTokenFormat({ token })) {
        return null;
    }

    try {
        const parts = token.split('.');
        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
        return payload;
    } catch (error) {
        return null;
    }
};

/**
 * Obtém tempo de expiração do token
 * @param {string} token - Token JWT
 * @returns {Date|null} Data de expiração ou null
 */
const getTokenExpiration = ({ token = '' } = {}) => {
    const payload = extractPayload({ token });
    if (!payload || !payload.exp) {
        return null;
    }
    return new Date(payload.exp * 1000);
};

/**
 * Calcula tempo restante do token
 * @param {string} token - Token JWT
 * @returns {number} Tempo restante em segundos
 */
const getTokenTimeRemaining = ({ token = '' } = {}) => {
    const expiration = getTokenExpiration({ token });
    if (!expiration) {
        return 0;
    }

    const now = Math.floor(Date.now() / 1000);
    const exp = Math.floor(expiration.getTime() / 1000);
    return Math.max(0, exp - now);
};

/**
 * Verifica se token está próximo de expirar
 * @param {string} token - Token JWT
 * @param {number} threshold - Limite em segundos (padrão: 5 minutos)
 * @returns {boolean} true se próximo de expirar
 */
const isTokenNearExpiration = ({ token = '', threshold = 300 } = {}) => {
    const timeRemaining = getTokenTimeRemaining({ token });
    return timeRemaining <= threshold;
};

/**
 * Gera token de teste para desenvolvimento
 * @param {Object} payload - Payload do token
 * @param {string} secret - Secret para assinatura
 * @returns {string} Token de teste
 */
const generateTestToken = ({ payload = {}, secret = 'test-secret' } = {}) => {
    const jwt = require('jsonwebtoken');
    return jwt.sign(payload, secret, { expiresIn: '1h' });
};

module.exports = {
    extractTokenFromHeader,
    formatAuthHeader,
    hashToken,
    verifyTokenHash,
    calculateTokenExpiration,
    isValidTokenFormat,
    extractPayload,
    getTokenExpiration,
    getTokenTimeRemaining,
    isTokenNearExpiration,
    generateTestToken
};
