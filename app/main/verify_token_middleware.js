const jwt = require('jsonwebtoken');
const { TokenBlacklist } = require('../../models');
const config = require('../../config/config');
const logger = require('../../utils/logger');
const UserProvider = require('../../providers/user_provider');

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
                message: 'Access token is required'
            });
        }

        // Check if token is blacklisted
        const isBlacklisted = await TokenBlacklist.findOne({
            where: { token }
        });

        if (isBlacklisted) {
            return res.status(401).json({
                success: false,
                message: 'Invalid token'
            });
        }

        // Verify token
        const decoded = jwt.verify(token, config.jwt.secret);

        // Get user info via UserProvider
        const userProvider = new UserProvider();
        const response = await userProvider.getUserById(decoded.userId);
        const user = response.user;

        if (!user || !user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'User not found or inactive'
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
                message: 'Invalid token'
            });
        }

        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token expired'
            });
        }

        return res.status(500).json({
            success: false,
            message: 'Internal server error'
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
                message: 'Unauthorized access'
            });
        }

        const userRole = req.user.role;
        const allowedRoles = Array.isArray(roles) ? roles : [roles];

        if (!allowedRoles.includes(userRole)) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Insufficient permissions.'
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
            message: 'Unauthorized access'
        });
    }

    if (!req.user.isEmailVerified) {
        return res.status(403).json({
            success: false,
            message: 'Email not verified. Please verify your email before continuing.'
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
            throw new Error('Token is required');
        }

        // Check if token is blacklisted
        const isBlacklisted = await TokenBlacklist.findOne({
            where: { token }
        });

        if (isBlacklisted) {
            throw new Error('Invalid token');
        }

        // Verify token
        const decoded = jwt.verify(token, config.jwt.secret);

        // Get user info
        const user = await User.findByPk(decoded.userId, {
            attributes: ['id', 'email', 'name', 'role', 'isActive', 'isEmailVerified']
        });

        if (!user || !user.isActive) {
            throw new Error('User not found or inactive');
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
