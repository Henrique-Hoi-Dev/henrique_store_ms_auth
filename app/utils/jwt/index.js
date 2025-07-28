/**
 * JWT Utilities - Módulo Principal
 *
 * Este módulo centraliza todas as funções JWT organizadas por categoria:
 * - Token Generators: Geração de diferentes tipos de tokens
 * - Token Validators: Validação e verificação de tokens
 * - Token Utils: Funções utilitárias para manipulação de tokens
 */

const tokenGenerators = require('./token-generators');
const tokenValidators = require('./token-validators');
const tokenUtils = require('./token-utils');

// Exporta todas as funções organizadas por categoria
module.exports = {
    // Token Generators
    ...tokenGenerators,

    // Token Validators
    ...tokenValidators,

    // Token Utils
    ...tokenUtils,

    // Categorias para importação específica
    generators: tokenGenerators,
    validators: tokenValidators,
    utils: tokenUtils
};
