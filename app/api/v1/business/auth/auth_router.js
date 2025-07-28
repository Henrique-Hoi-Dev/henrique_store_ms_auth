const express = require('express');
const router = express.Router();
const AuthController = require('./auth_controller');
const validation = require('./auth_validation');
const validator = require('../../../../utils/validator');

const authController = new AuthController();

/**
 * Authentication Routes
 * All routes are public (no authentication required)
 */

// User registration
router.post('/register', validator(validation.register), authController.register.bind(authController));

// User login
router.post('/login', validator(validation.login), authController.login.bind(authController));

// Google OAuth2 Authentication
router.post(
    '/google',
    validator(validation.authenticateWithGoogle),
    authController.authenticateWithGoogle.bind(authController)
);

// Token refresh
router.post('/refresh', validator(validation.refreshToken), authController.refreshToken.bind(authController));

// Logout
router.post('/logout', validator(validation.logout), authController.logout.bind(authController));

// Token verification
router.get('/verify-token', authController.verifyToken.bind(authController));

// Complete login with 2FA
router.post(
    '/complete-2fa',
    validator(validation.complete2FA),
    authController.completeLoginWith2FA.bind(authController)
);

// Complete Google OAuth2 login with 2FA
router.post(
    '/google/complete-2fa',
    validator(validation.completeGoogle2FA),
    authController.completeGoogleLoginWith2FA.bind(authController)
);

module.exports = router;
