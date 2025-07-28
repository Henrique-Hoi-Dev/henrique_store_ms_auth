const { body, param, query } = require('express-validation');

/**
 * Authentication validation rules
 */
const validation = {
    /**
     * User registration validation
     */
    register: [
        body('email').isEmail().withMessage('Email deve ser válido').normalizeEmail(),
        body('password')
            .isLength({ min: 8 })
            .withMessage('Senha deve ter pelo menos 8 caracteres')
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
            .withMessage('Senha deve conter pelo menos uma letra maiúscula, uma minúscula e um número'),
        body('name')
            .isLength({ min: 2, max: 100 })
            .withMessage('Nome deve ter entre 2 e 100 caracteres')
            .matches(/^[a-zA-ZÀ-ÿ\s]+$/)
            .withMessage('Nome deve conter apenas letras e espaços'),
        body('role').optional().isIn(['BUYER', 'SELLER', 'ADMIN']).withMessage('Role deve ser BUYER, SELLER ou ADMIN')
    ],

    /**
     * User login validation
     */
    login: [
        body('email').isEmail().withMessage('Email deve ser válido').normalizeEmail(),
        body('password').notEmpty().withMessage('Senha é obrigatória')
    ],

    /**
     * Google OAuth2 authentication validation
     */
    authenticateWithGoogle: [
        body('code')
            .notEmpty()
            .withMessage('Código de autorização é obrigatório')
            .isString()
            .withMessage('Código deve ser uma string')
    ],

    /**
     * Token refresh validation
     */
    refreshToken: [
        body('refreshToken')
            .notEmpty()
            .withMessage('Refresh token é obrigatório')
            .isString()
            .withMessage('Refresh token deve ser uma string')
    ],

    /**
     * Logout validation
     */
    logout: [
        body('accessToken').optional().isString().withMessage('Access token deve ser uma string'),
        body('refreshToken').optional().isString().withMessage('Refresh token deve ser uma string')
    ],

    /**
     * Complete 2FA validation
     */
    complete2FA: [
        body('userId')
            .notEmpty()
            .withMessage('ID do usuário é obrigatório')
            .isUUID()
            .withMessage('ID do usuário deve ser um UUID válido'),
        body('token')
            .notEmpty()
            .withMessage('Token 2FA é obrigatório')
            .isString()
            .withMessage('Token deve ser uma string'),
        body('method').isIn(['totp', 'backup']).withMessage('Método deve ser "totp" ou "backup"')
    ],

    /**
     * Complete Google 2FA validation
     */
    completeGoogle2FA: [
        body('userId')
            .notEmpty()
            .withMessage('ID do usuário é obrigatório')
            .isUUID()
            .withMessage('ID do usuário deve ser um UUID válido'),
        body('token')
            .notEmpty()
            .withMessage('Token 2FA é obrigatório')
            .isString()
            .withMessage('Token deve ser uma string'),
        body('method').isIn(['totp', 'backup']).withMessage('Método deve ser "totp" ou "backup"')
    ]
};

module.exports = validation;
