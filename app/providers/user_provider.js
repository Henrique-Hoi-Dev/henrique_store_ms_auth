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
            const response = await this.client.post('/users/validate-credentials', {
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
     * Create a new user
     * @param {Object} userData - User data
     * @returns {Promise<Object>} Created user data
     */
    async createUser(userData) {
        try {
            const response = await this.client.post('/users', userData);
            return response.data;
        } catch (error) {
            if (error.response?.status === 409) {
                throw new Error('Email já cadastrado');
            }
            if (error.response?.status === 422) {
                throw new Error('Dados inválidos para criação do usuário');
            }
            throw new Error('Erro ao criar usuário');
        }
    }

    /**
     * Get user by ID
     * @param {string} userId - User ID
     * @returns {Promise<Object>} User data
     */
    async getUserById(userId) {
        try {
            const response = await this.client.get(`/users/${userId}`);
            return response.data;
        } catch (error) {
            if (error.response?.status === 404) {
                throw new Error('Usuário não encontrado');
            }
            throw new Error('Erro ao buscar usuário');
        }
    }

    /**
     * Handle Google OAuth2 authentication
     * @param {Object} googleData - Google user data
     * @returns {Promise<Object>} User data
     */
    async handleGoogleAuth(googleData) {
        try {
            const response = await this.client.post('/users/google-auth', googleData);
            return response.data;
        } catch (error) {
            if (error.response?.status === 422) {
                throw new Error('Dados inválidos para autenticação Google');
            }
            throw new Error('Erro na autenticação Google');
        }
    }

    /**
     * Update user last login
     * @param {string} userId - User ID
     * @returns {Promise<Object>} Updated user data
     */
    async updateLastLogin(userId) {
        try {
            const response = await this.client.patch(`/users/${userId}/last-login`);
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
            const response = await this.client.get(`/users/${userId}/2fa-info`);
            return response.data;
        } catch (error) {
            if (error.response?.status === 404) {
                throw new Error('Usuário não encontrado');
            }
            throw new Error('Erro ao buscar informações 2FA');
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
