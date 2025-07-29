const logger = require('../utils/logger');
const BaseIntegration = require('../api/v1/base/base_integration');

class NotificationProvider extends BaseIntegration {
    constructor() {
        super('NOTIFICATION_MS');
    }

    /**
     * Send welcome email
     * @param {string} email - User email
     * @param {string} name - User name
     * @returns {Promise<Object>} Notification result
     */
    async sendWelcomeEmail(email, name) {
        try {
            const response = await this.client.post('/notifications/email/welcome', {
                email,
                name,
                template: 'welcome'
            });
            return response.data;
        } catch (error) {
            logger.warn('Failed to send welcome email:', error.message);
            // Don't throw error as this is not critical for auth flow
            return null;
        }
    }

    /**
     * Send verification email
     * @param {string} email - User email
     * @param {string} token - Verification token
     * @returns {Promise<Object>} Notification result
     */
    async sendVerificationEmail(email, token) {
        try {
            const response = await this.client.post('/notifications/email/verification', {
                email,
                token,
                template: 'email-verification'
            });
            return response.data;
        } catch (error) {
            logger.warn('Failed to send verification email:', error.message);
            // Don't throw error as this is not critical for auth flow
            return null;
        }
    }

    /**
     * Send password reset email
     * @param {string} email - User email
     * @param {string} token - Reset token
     * @returns {Promise<Object>} Notification result
     */
    async sendPasswordResetEmail(email, token) {
        try {
            const response = await this.client.post('/notifications/email/password-reset', {
                email,
                token,
                template: 'password-reset'
            });
            return response.data;
        } catch (error) {
            logger.warn('Failed to send password reset email:', error.message);
            return null;
        }
    }

    /**
     * Send 2FA setup email
     * @param {string} email - User email
     * @param {string} secret - 2FA secret
     * @returns {Promise<Object>} Notification result
     */
    async send2FASetupEmail(email, secret) {
        try {
            const response = await this.client.post('/notifications/email/2fa-setup', {
                email,
                secret,
                template: '2fa-setup'
            });
            return response.data;
        } catch (error) {
            logger.warn('Failed to send 2FA setup email:', error.message);
            return null;
        }
    }

    /**
     * Send SMS notification
     * @param {string} phone - User phone number
     * @param {string} message - SMS message
     * @returns {Promise<Object>} Notification result
     */
    async sendSMS(phone, message) {
        try {
            const response = await this.client.post('/notifications/sms', {
                phone,
                message
            });
            return response.data;
        } catch (error) {
            logger.warn('Failed to send SMS:', error.message);
            return null;
        }
    }

    /**
     * Health check for notification service
     * @returns {Promise<boolean>} Service health status
     */
    async healthCheck() {
        try {
            const response = await this.client.get('/health');
            return response.status === 200;
        } catch (error) {
            logger.error('Notification service health check failed:', error.message);
            return false;
        }
    }
}

module.exports = NotificationProvider;
