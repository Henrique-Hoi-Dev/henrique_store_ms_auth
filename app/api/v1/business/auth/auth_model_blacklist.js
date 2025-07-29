'use strict';

const { DataTypes } = require('sequelize');
const { sequelize } = require('../../../../../config/database');

const AuthModelBlacklist = sequelize.define(
    'TokenBlacklist',
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

module.exports = AuthModelBlacklist;
