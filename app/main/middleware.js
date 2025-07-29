// Removed express-validation dependency
const _ = require('lodash');
const ValidationsErrorHandler = require('./validations_error_handler');
const keys = require('../../app/utils/error_mapping');
const message = require('../../locale/error/en.json');
const jwt = require('jsonwebtoken');

const { validVerifyToken } = require('../../app/utils/jwt');
const { isSessionValid, globalBlacklist } = require('../../app/utils/token-blacklist');

const validationsErrorHandler = new ValidationsErrorHandler();

const logger = require('../utils/logger');

function logError(err, req, res, next) {
    try {
        if (err) {
            logger.error('logError');
            logger.error(err);
            logger.error(JSON.stringify(err, null, 2));
            return next(err);
        } else {
            return next();
        }
    } catch (error) {
        logger.error('logError catch');
        logger.error(error);

        if (err) {
            return next(err);
        } else {
            return next();
        }
    }
}

function handleError(err, req, res, next) {
    if (err) {
        // Verificar se err tem propriedades válidas antes de acessá-las
        if (err.response && err.response.status && err.response.data) {
            res.status(err.response.status).json(err.response.data);
            return;
        }

        err.key = err.key || err.message || 'UNKNOWN_ERROR';
        err.errorCode = keys[err.key] || 500;

        err.message = message[err.key] || err.message || 'Internal server error';

        if (err.error === 'Unprocessable Entity' || err.errors) {
            err = validationsErrorHandler.errorResponse(err);
        } else if (err instanceof Error) {
            err = _.pick(err, [
                'message',
                'status',
                'key',
                'errorCode',
                'local',
                'field',
                'reasons',
                'registered',
                'rejected'
            ]);
        }

        const status = err.status || 422;
        delete err.status;
        res.status(status).json(err);
    } else {
        next();
    }
}

function throw404(req, res, next) {
    let err = new Error();
    err.status = 404;
    err.message = 'API_ENDPOINT_NOT_FOUND';
    next(err);
}

async function verifyToken(req, res, next) {
    try {
        const token = req.header('Authorization').replace('Bearer ', '');

        if (!token) {
            const error = new Error('TOKEN_REQUIRED');
            error.status = 401;
            error.key = 'TOKEN_REQUIRED';
            return next(error);
        }

        try {
            const decodedToken = validVerifyToken({ token });

            if (globalBlacklist.isBlacklisted(token)) {
                const error = new Error('TOKEN_BLACKLISTED');
                error.status = 401;
                error.key = 'TOKEN_BLACKLISTED';
                return next(error);
            }

            const isValid = await isSessionValid(decodedToken.id, decodedToken.iat);
            if (!isValid) {
                const error = new Error('SESSION_INVALIDATED');
                error.status = 401;
                error.key = 'SESSION_INVALIDATED';
                return next(error);
            }

            req.locals = { ...req.locals, user: decodedToken };
            next();
        } catch (jwtError) {
            logger.error('JWT Verification Error:', jwtError);

            let errorMessage = 'INVALID_TOKEN';
            let errorKey = 'INVALID_TOKEN';

            if (jwtError instanceof jwt.TokenExpiredError) {
                errorMessage = 'TOKEN_EXPIRED';
                errorKey = 'TOKEN_EXPIRED';
            } else if (jwtError instanceof jwt.JsonWebTokenError) {
                errorMessage = 'INVALID_TOKEN_SIGNATURE';
                errorKey = 'INVALID_TOKEN_SIGNATURE';
            } else if (jwtError instanceof jwt.NotBeforeError) {
                errorMessage = 'TOKEN_NOT_ACTIVE';
                errorKey = 'TOKEN_NOT_ACTIVE';
            }

            const error = new Error(errorMessage);
            error.status = 401;
            error.key = errorKey;
            next(error);
        }
    } catch (err) {
        logger.error('Token verification error:', err);
        const error = new Error('INVALID_TOKEN');
        error.status = 401;
        error.key = 'INVALID_TOKEN';
        next(error);
    }
}

async function ensureAuthorization(req, res, next) {
    const authHeader = req.header('Authorization');

    if (!authHeader) {
        const err = new Error('TOKEN_REQUIRED');
        err.status = 401;
        err.key = 'TOKEN_REQUIRED';
        return next(err);
    }

    if (!authHeader.startsWith('Bearer ')) {
        const err = new Error('INVALID_TOKEN_FORMAT');
        err.status = 401;
        err.key = 'INVALID_TOKEN_FORMAT';
        return next(err);
    }

    next();
}

function errorHandler(err, req, res, next) {
    console.error(err);

    // Handle specific JWT errors
    if (err.key === 'TOKEN_EXPIRED') {
        return res.status(401).json({
            error: {
                message: 'Token expired. Please login again.',
                status: 401,
                key: 'TOKEN_EXPIRED',
                errorCode: keys['TOKEN_EXPIRED'] || 401
            }
        });
    }

    if (err.key === 'TOKEN_REQUIRED') {
        return res.status(401).json({
            error: {
                message: 'Authentication token is required.',
                status: 401,
                key: 'TOKEN_REQUIRED',
                errorCode: keys['TOKEN_REQUIRED'] || 401
            }
        });
    }

    if (err.key === 'INVALID_TOKEN_FORMAT') {
        return res.status(401).json({
            error: {
                message: 'Invalid token format. Use: Bearer <token>',
                status: 401,
                key: 'INVALID_TOKEN_FORMAT',
                errorCode: keys['INVALID_TOKEN_FORMAT'] || 401
            }
        });
    }

    if (err.key === 'INVALID_TOKEN_SIGNATURE') {
        return res.status(401).json({
            error: {
                message: 'Invalid token signature.',
                status: 401,
                key: 'INVALID_TOKEN_SIGNATURE',
                errorCode: keys['INVALID_TOKEN_SIGNATURE'] || 401
            }
        });
    }

    if (err.key === 'TOKEN_NOT_ACTIVE') {
        return res.status(401).json({
            error: {
                message: 'Token is not yet active.',
                status: 401,
                key: 'TOKEN_NOT_ACTIVE',
                errorCode: keys['TOKEN_NOT_ACTIVE'] || 401
            }
        });
    }

    if (err.key === 'TOKEN_BLACKLISTED') {
        return res.status(401).json({
            error: {
                message: 'Token has been invalidated. Please login again.',
                status: 401,
                key: 'TOKEN_BLACKLISTED',
                errorCode: keys['TOKEN_BLACKLISTED'] || 401
            }
        });
    }

    if (err.key === 'SESSION_INVALIDATED') {
        return res.status(401).json({
            error: {
                message: 'Session has been invalidated. Please login again.',
                status: 401,
                key: 'SESSION_INVALIDATED',
                errorCode: keys['SESSION_INVALIDATED'] || 401
            }
        });
    }

    if (err.key === 'SESSION_VALIDATION_ERROR') {
        return res.status(401).json({
            error: {
                message: 'Session validation error. Please login again.',
                status: 401,
                key: 'SESSION_VALIDATION_ERROR',
                errorCode: keys['SESSION_VALIDATION_ERROR'] || 401
            }
        });
    }

    res.status(err.status || 500).json({
        error: {
            message: err.message || 'Internal server error',
            status: err.status || 500,
            key: err.key || 'INTERNAL_SERVER_ERROR',
            errorCode: keys[err.key] || 500
        }
    });
}

module.exports = {
    errorHandler,
    logError,
    handleError,
    throw404,
    verifyToken,
    ensureAuthorization
};
