const { Joi } = require('express-validation');

module.exports = {
    generateTokens: {
        body: Joi.object({
            userId: Joi.string().required().messages({
                'any.required': 'User ID is required',
                'string.base': 'User ID must be a string'
            }),
            email: Joi.string().email().normalize().required().messages({
                'string.email': 'Email must be valid',
                'any.required': 'Email is required'
            }),
            role: Joi.string().valid('BUYER', 'SELLER', 'ADMIN').required().messages({
                'any.only': 'Role must be BUYER, SELLER or ADMIN',
                'any.required': 'Role is required'
            })
        })
    },
    verifyToken: {
        body: Joi.object({
            token: Joi.string().required().messages({
                'any.required': 'Token is required',
                'string.base': 'Token must be a string'
            })
        })
    },
    logout: {
        body: Joi.object({
            token: Joi.string().optional().allow('').messages({
                'string.base': 'Token must be a string'
            })
        }).unknown(true)
    },
    forgotPassword: {
        body: Joi.object({
            email: Joi.string().email().normalize().required().messages({
                'string.email': 'Email must be valid',
                'any.required': 'Email is required'
            }),
            userId: Joi.string().required().messages({
                'any.required': 'User ID is required',
                'string.base': 'User ID must be a string'
            })
        })
    },
    verifyResetToken: {
        body: Joi.object({
            token: Joi.string().required().messages({
                'any.required': 'Token is required',
                'string.base': 'Token must be a string'
            })
        })
    },
    confirmPasswordReset: {
        body: Joi.object({
            token: Joi.string().required().messages({
                'any.required': 'Token is required',
                'string.base': 'Token must be a string'
            }),
            userId: Joi.string().required().messages({
                'any.required': 'User ID is required',
                'string.base': 'User ID must be a string'
            })
        })
    },
    verifyEmailToken: {
        body: Joi.object({
            token: Joi.string().required().messages({
                'any.required': 'Token is required',
                'string.base': 'Token must be a string'
            })
        })
    },
    resendVerification: {
        body: Joi.object({
            email: Joi.string().email().normalize().required().messages({
                'string.email': 'Email must be valid',
                'any.required': 'Email is required'
            }),
            userId: Joi.string().required().messages({
                'any.required': 'User ID is required',
                'string.base': 'User ID must be a string'
            })
        })
    }
};
