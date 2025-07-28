const crypto = require('crypto');

/**
 * Sistema de Blacklist de Tokens
 * Permite invalidar tokens JWT após logout
 */
class TokenBlacklist {
    constructor() {
        this.blacklistedTokens = new Set();
        this.tokenExpiry = new Map(); // Para limpeza automática
    }

    /**
     * Gera hash do token para armazenamento seguro
     * @param {string} token - Token JWT
     * @returns {string} Hash do token
     */
    hashToken(token) {
        return crypto.createHash('sha256').update(token).digest('hex');
    }

    /**
     * Adiciona token à blacklist
     * @param {string} token - Token JWT a ser invalidado
     * @param {number} expiresIn - Tempo de expiração em segundos (opcional)
     */
    blacklistToken(token, expiresIn = null) {
        const hash = this.hashToken(token);
        this.blacklistedTokens.add(hash);

        // Se não especificado, usar expiração padrão (24h)
        const expiryTime = expiresIn || 24 * 60 * 60 * 1000; // 24 horas em ms
        const expiryDate = Date.now() + expiryTime;

        this.tokenExpiry.set(hash, expiryDate);

        // Limpeza automática após expiração
        setTimeout(() => {
            this.removeFromBlacklist(hash);
        }, expiryTime);

        console.log(`Token adicionado à blacklist. Expira em: ${new Date(expiryDate).toISOString()}`);
    }

    /**
     * Verifica se token está na blacklist
     * @param {string} token - Token JWT a ser verificado
     * @returns {boolean} true se token está na blacklist
     */
    isBlacklisted(token) {
        const hash = this.hashToken(token);
        return this.blacklistedTokens.has(hash);
    }

    /**
     * Remove token da blacklist
     * @param {string} hash - Hash do token
     */
    removeFromBlacklist(hash) {
        this.blacklistedTokens.delete(hash);
        this.tokenExpiry.delete(hash);
        console.log(`Token removido da blacklist: ${hash}`);
    }

    /**
     * Limpa tokens expirados da blacklist
     */
    cleanupExpiredTokens() {
        const now = Date.now();
        for (const [hash, expiry] of this.tokenExpiry.entries()) {
            if (now > expiry) {
                this.removeFromBlacklist(hash);
            }
        }
    }

    /**
     * Retorna estatísticas da blacklist
     * @returns {Object} Estatísticas da blacklist
     */
    getStats() {
        return {
            totalTokens: this.blacklistedTokens.size,
            totalExpiry: this.tokenExpiry.size,
            blacklistedTokens: Array.from(this.blacklistedTokens),
            expiryMap: Object.fromEntries(this.tokenExpiry)
        };
    }
}

/**
 * Middleware para verificar se token está na blacklist
 * @param {TokenBlacklist} blacklist - Instância da blacklist
 * @returns {Function} Middleware Express
 */
function checkTokenBlacklist(blacklist) {
    return (req, res, next) => {
        try {
            const authHeader = req.header('Authorization');
            if (!authHeader) {
                return next(); // Deixar outros middlewares lidarem com token ausente
            }

            const token = authHeader.replace('Bearer ', '');
            if (!token) {
                return next(); // Deixar outros middlewares lidarem com formato inválido
            }

            // Verificar se token está na blacklist
            if (blacklist.isBlacklisted(token)) {
                const error = new Error('TOKEN_BLACKLISTED');
                error.status = 401;
                error.key = 'TOKEN_BLACKLISTED';
                return next(error);
            }

            next();
        } catch (error) {
            next(error);
        }
    };
}

/**
 * Função para invalidar token no banco de dados
 * @param {string} userId - ID do usuário
 * @param {string} token - Token JWT (opcional, para hash)
 */
async function invalidateUserSession(user, token = null) {
    try {
        // Atualizar last_logout
        user.last_logout = new Date();

        // Se token fornecido, salvar hash para tracking (opcional)
        if (token) {
            const blacklist = new TokenBlacklist();
            const tokenHash = blacklist.hashToken(token);
            user.last_token_hash = tokenHash; // Campo opcional para tracking
        }

        await user.save();

        console.log(`Sessão invalidada para usuário ${user.id} em ${user.last_logout.toISOString()}`);
        return true;
    } catch (error) {
        console.error('Erro ao invalidar sessão:', error);
        throw error;
    }
}

/**
 * Função para verificar se sessão foi invalidada
 * @param {string} user - ID do usuário
 * @param {Date} tokenIssuedAt - Data de emissão do token (iat)
 * @returns {boolean} true se sessão é válida
 */
async function isSessionValid(user, tokenIssuedAt) {
    try {
        if (!user || !user.last_logout) {
            return true;
        }

        const tokenIssuedDate = new Date(tokenIssuedAt * 1000);

        return tokenIssuedDate > user.last_logout;
    } catch (error) {
        console.error('Erro ao verificar sessão:', error);
        return false; // Em caso de erro, considerar inválida por segurança
    }
}

// Instância global da blacklist
const globalBlacklist = new TokenBlacklist();

// Limpeza automática a cada 1 hora
setInterval(
    () => {
        globalBlacklist.cleanupExpiredTokens();
    },
    60 * 60 * 1000
);

module.exports = {
    TokenBlacklist,
    globalBlacklist,
    checkTokenBlacklist: () => checkTokenBlacklist(globalBlacklist),
    invalidateUserSession,
    isSessionValid
};
