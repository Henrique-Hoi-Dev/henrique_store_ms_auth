const Joi = require('joi');

/**
 * Authentication validation schemas using Joi
 */
const validation = {
    /**
     * Generate tokens validation
     */
    generateTokens: Joi.object({
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
    }),

    /**
     * Verify token validation
     */
    verifyToken: Joi.object({
        token: Joi.string().required().messages({
            'any.required': 'Token is required',
            'string.base': 'Token must be a string'
        })
    }),

    /**
     * Logout validation
     */
    logout: Joi.object({
        token: Joi.string().required().messages({
            'any.required': 'Token is required',
            'string.base': 'Token must be a string'
        })
    }),

    /**
     * Forgot password validation
     */
    forgotPassword: Joi.object({
        email: Joi.string().email().normalize().required().messages({
            'string.email': 'Email must be valid',
            'any.required': 'Email is required'
        }),
        userId: Joi.string().required().messages({
            'any.required': 'User ID is required',
            'string.base': 'User ID must be a string'
        })
    }),

    /**
     * Verify reset token validation
     */
    verifyResetToken: Joi.object({
        token: Joi.string().required().messages({
            'any.required': 'Token is required',
            'string.base': 'Token must be a string'
        })
    }),

    /**
     * Confirm password reset validation
     */
    confirmPasswordReset: Joi.object({
        token: Joi.string().required().messages({
            'any.required': 'Token is required',
            'string.base': 'Token must be a string'
        }),
        userId: Joi.string().required().messages({
            'any.required': 'User ID is required',
            'string.base': 'User ID must be a string'
        })
    }),

    /**
     * Verify email token validation
     */
    verifyEmailToken: Joi.object({
        token: Joi.string().required().messages({
            'any.required': 'Token is required',
            'string.base': 'Token must be a string'
        })
    }),

    /**
     * Resend verification validation
     */
    resendVerification: Joi.object({
        email: Joi.string().email().normalize().required().messages({
            'string.email': 'Email must be valid',
            'any.required': 'Email is required'
        }),
        userId: Joi.string().required().messages({
            'any.required': 'User ID is required',
            'string.base': 'User ID must be a string'
        })
    })
};

module.exports = validation;
