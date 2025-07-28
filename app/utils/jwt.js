/**
 * JWT Utilities - Arquivo Principal (Legacy)
 *
 * Este arquivo mantém compatibilidade com imports existentes.
 * Para novos projetos, use a estrutura modular em /jwt/
 */

// Importa diretamente dos módulos específicos
const tokenGenerators = require('./jwt/token-generators');
const tokenValidators = require('./jwt/token-validators');
const tokenUtils = require('./jwt/token-utils');

module.exports = {
    // Funções principais (mantidas para compatibilidade)
    generateToken: tokenGenerators.generateToken,
    validVerifyToken: tokenValidators.validVerifyToken,
    decodeToken: tokenValidators.decodeToken,
    isTokenExpired: tokenValidators.isTokenExpired,

    // Funções específicas por tipo de token
    generateAccessToken: tokenGenerators.generateAccessToken,
    generateRefreshToken: tokenGenerators.generateRefreshToken,
    generateResetToken: tokenGenerators.generateResetToken,
    generateEmailVerificationToken: tokenGenerators.generateEmailVerificationToken,

    // Funções utilitárias
    extractTokenFromHeader: tokenUtils.extractTokenFromHeader,
    isTokenType: tokenValidators.isTokenType,
    getUserFromToken: tokenValidators.getUserFromToken,

    // Novas funções utilitárias
    formatAuthHeader: tokenUtils.formatAuthHeader,
    isValidTokenFormat: tokenUtils.isValidTokenFormat,
    extractPayload: tokenUtils.extractPayload,
    getTokenExpiration: tokenUtils.getTokenExpiration,
    getTokenTimeRemaining: tokenUtils.getTokenTimeRemaining,
    isTokenNearExpiration: tokenUtils.isTokenNearExpiration,
    generateTestToken: tokenUtils.generateTestToken,

    // Funções de hash e expiração
    hashToken: tokenUtils.hashToken,
    verifyTokenHash: tokenUtils.verifyTokenHash,
    calculateTokenExpiration: tokenUtils.calculateTokenExpiration,

    // Categorias para importação específica
    generators: tokenGenerators,
    validators: tokenValidators,
    utils: tokenUtils
};
