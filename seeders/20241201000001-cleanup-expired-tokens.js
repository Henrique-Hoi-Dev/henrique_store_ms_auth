'use strict';

const { TokenBlacklist } = require('../models');

module.exports = {
    up: async (queryInterface, Sequelize) => {
        // Clean up expired tokens
        await TokenBlacklist.destroy({
            where: {
                expiresAt: {
                    [Sequelize.Op.lt]: new Date()
                }
            }
        });

        console.log('Expired tokens cleaned up');
    },

    down: async (queryInterface, Sequelize) => {
        // No rollback needed for cleanup
        console.log('Cleanup operation cannot be rolled back');
    }
}; 