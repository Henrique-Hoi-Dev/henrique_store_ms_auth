'use strict';

const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
    class AuthModelBlacklist extends Model {
        static associate(models) {
            // No associations needed for token blacklist
        }
    }

    AuthModelBlacklist.init(
        {
            id: {
                type: DataTypes.INTEGER,
                primaryKey: true,
                autoIncrement: true,
                allowNull: false
            },
            token: {
                type: DataTypes.TEXT,
                allowNull: false,
                unique: true
            },
            type: {
                type: DataTypes.ENUM('access', 'refresh'),
                allowNull: false
            },
            expiresAt: {
                type: DataTypes.DATE,
                allowNull: false
            }
        },
        {
            sequelize,
            modelName: 'TokenBlacklist',
            tableName: 'token_blacklist',
            timestamps: true,
            indexes: [
                {
                    unique: true,
                    fields: ['token']
                },
                {
                    fields: ['expiresAt']
                },
                {
                    fields: ['type']
                }
            ]
        }
    );

    return AuthModelBlacklist;
};
