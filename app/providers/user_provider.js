const logger = require('../utils/logger');
const BaseIntegration = require('../api/v1/base/base_integration');

class UserProvider extends BaseIntegration {
    constructor() {
        super('USER_MS');
        this.client = this.httpClient;
    }

    /**
     * Validate user credentials
     * @param {string} email - User email
     * @param {string} password - User password
     * @returns {Promise<Object>} User data if credentials are valid
     */
    async validateCredentials(email, password) {
        try {
            const response = await this.client.post('/validate-credentials', {
                email: email.toLowerCase(),
                password
            });
            return response.data;
        } catch (error) {
            if (error.response?.status === 401) {
                throw new Error('Credenciais inválidas');
            }
            if (error.response?.status === 423) {
                throw new Error('Conta temporariamente bloqueada. Tente novamente mais tarde.');
            }
            throw new Error('Erro ao validar credenciais');
        }
    }

    /**
     * Get user by ID
     * @param {string} userId - User ID
     * @returns {Promise<Object>} User data
     */
    async getUserById(userId) {
        try {
            const response = await this.client.get(`/${userId}`);
            return response.data;
        } catch (error) {
            if (error.response?.status === 404) {
                throw new Error('User not found');
            }
            throw new Error('Error fetching user');
        }
    }

    /**
     * Handle Google OAuth2 authentication
     * @param {Object} googleData - Google user data
     * @returns {Promise<Object>} User data
     */
    async handleGoogleAuth(googleData) {
        try {
            const response = await this.client.post('/google-auth', googleData);
            return response.data;
        } catch (error) {
            if (error.response?.status === 422) {
                throw new Error('Invalid data for Google authentication');
            }
            throw new Error('Google authentication error');
        }
    }

    /**
     * Update user last login
     * @param {string} userId - User ID
     * @returns {Promise<Object>} Updated user data
     */
    async updateLastLogin(userId) {
        try {
            const response = await this.client.patch(`/${userId}/last-login`);
            return response.data;
        } catch (error) {
            logger.warn('Failed to update last login:', error.message);
            // Don't throw error as this is not critical
            return null;
        }
    }

    /**
     * Get user 2FA information
     * @param {string} userId - User ID
     * @returns {Promise<Object>} User 2FA data
     */
    async getUser2FAInfo(userId) {
        try {
            const response = await this.client.get(`/${userId}/2fa-info`);
            return response.data;
        } catch (error) {
            if (error.response?.status === 404) {
                throw new Error('User not found');
            }
            throw new Error('Error fetching 2FA information');
        }
    }

    /**
     * Health check for user service
     * @returns {Promise<boolean>} Service health status
     */
    async healthCheck() {
        try {
            const response = await this.client.get('/health');
            return response.status === 200;
        } catch (error) {
            logger.error('User service health check failed:', error.message);
            return false;
        }
    }
}

module.exports = UserProvider;
