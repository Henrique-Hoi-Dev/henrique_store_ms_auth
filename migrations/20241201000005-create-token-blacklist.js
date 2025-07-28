'use strict';

module.exports = {
    up: async (queryInterface, Sequelize) => {
        await queryInterface.createTable('token_blacklist', {
            id: {
                allowNull: false,
                autoIncrement: true,
                primaryKey: true,
                type: Sequelize.INTEGER
            },
            token: {
                type: Sequelize.TEXT,
                allowNull: false,
                unique: true
            },
            type: {
                type: Sequelize.ENUM('access', 'refresh'),
                allowNull: false
            },
            expiresAt: {
                type: Sequelize.DATE,
                allowNull: false
            },
            createdAt: {
                allowNull: false,
                type: Sequelize.DATE,
                defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
            },
            updatedAt: {
                allowNull: false,
                type: Sequelize.DATE,
                defaultValue: Sequelize.literal('CURRENT_TIMESTAMP')
            }
        });

        // Add indexes
        await queryInterface.addIndex('token_blacklist', ['token'], {
            unique: true,
            name: 'token_blacklist_token_unique'
        });

        await queryInterface.addIndex('token_blacklist', ['expiresAt'], {
            name: 'token_blacklist_expires_at_index'
        });

        await queryInterface.addIndex('token_blacklist', ['type'], {
            name: 'token_blacklist_type_index'
        });
    },

    down: async (queryInterface, Sequelize) => {
        await queryInterface.dropTable('token_blacklist');
    }
};
