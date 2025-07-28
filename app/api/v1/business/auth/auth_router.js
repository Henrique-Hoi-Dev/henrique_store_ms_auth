const express = require('express');
const router = express.Router();
const AuthController = require('./auth_controller');
const validation = require('./auth_validation');
const validator = require('../../../../utils/validator');

const authController = new AuthController();

// Core authentication endpoints
router.post(
    '/generate-tokens',
    validator(validation.generateTokens),
    authController.generateTokens.bind(authController)
);
router.post('/verify-token', validator(validation.verifyToken), authController.verifyToken.bind(authController));
router.post('/logout', validator(validation.logout), authController.logout.bind(authController));

// Password reset flow
router.post(
    '/forgot-password',
    validator(validation.forgotPassword),
    authController.forgotPassword.bind(authController)
);
router.post(
    '/verify-reset-token',
    validator(validation.verifyResetToken),
    authController.verifyResetToken.bind(authController)
);
router.post(
    '/confirm-password-reset',
    validator(validation.confirmPasswordReset),
    authController.confirmPasswordReset.bind(authController)
);

// Email verification flow
router.post(
    '/verify-email-token',
    validator(validation.verifyEmailToken),
    authController.verifyEmailToken.bind(authController)
);
router.post(
    '/resend-verification',
    validator(validation.resendVerification),
    authController.resendVerification.bind(authController)
);

module.exports = router;
