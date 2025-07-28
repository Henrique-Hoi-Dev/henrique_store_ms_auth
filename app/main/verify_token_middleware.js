const jwt = require('jsonwebtoken');
const { TokenBlacklist } = require('../../models');
const { User } = require('../../models');
const config = require('../../config/config');
const logger = require('../../utils/logger');

/**
 * Middleware to verify JWT token
 * Can be used by other microservices or via HTTP call
 */
const verifyToken = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Token de acesso é obrigatório'
            });
        }

        // Check if token is blacklisted
        const isBlacklisted = await TokenBlacklist.findOne({
            where: { token }
        });

        if (isBlacklisted) {
            return res.status(401).json({
                success: false,
                message: 'Token inválido'
            });
        }

        // Verify token
        const decoded = jwt.verify(token, config.jwt.secret);

        // Get user info
        const user = await User.findByPk(decoded.userId, {
            attributes: ['id', 'email', 'name', 'role', 'isActive', 'isEmailVerified']
        });

        if (!user || !user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'Usuário não encontrado ou inativo'
            });
        }

        // Add user info to request
        req.user = {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            isEmailVerified: user.isEmailVerified
        };

        next();
    } catch (error) {
        logger.error('Token verification error:', error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: 'Token inválido'
            });
        }

        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token expirado'
            });
        }

        return res.status(500).json({
            success: false,
            message: 'Erro interno do servidor'
        });
    }
};

/**
 * Middleware to require specific roles
 */
const requireRole = (roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Acesso não autorizado'
            });
        }

        const userRole = req.user.role;
        const allowedRoles = Array.isArray(roles) ? roles : [roles];

        if (!allowedRoles.includes(userRole)) {
            return res.status(403).json({
                success: false,
                message: 'Acesso negado. Permissão insuficiente.'
            });
        }

        next();
    };
};

/**
 * Middleware to require email verification
 */
const requireEmailVerification = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({
            success: false,
            message: 'Acesso não autorizado'
        });
    }

    if (!req.user.isEmailVerified) {
        return res.status(403).json({
            success: false,
            message: 'Email não verificado. Verifique seu email antes de continuar.'
        });
    }

    next();
};

/**
 * Function to verify token programmatically
 * Can be used by other microservices
 */
const verifyTokenProgrammatically = async (token) => {
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
        const decoded = jwt.verify(token, config.jwt.secret);

        // Get user info
        const user = await User.findByPk(decoded.userId, {
            attributes: ['id', 'email', 'name', 'role', 'isActive', 'isEmailVerified']
        });

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
        logger.error('Programmatic token verification error:', error);
        throw error;
    }
};

module.exports = {
    verifyToken,
    requireRole,
    requireEmailVerification,
    verifyTokenProgrammatically
};
