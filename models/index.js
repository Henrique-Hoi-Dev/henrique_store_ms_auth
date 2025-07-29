const { sequelize } = require('../config/database');
const AuthModelBlacklist = require('../app/api/v1/business/auth/auth_model_blacklist');

// Sync models with database
const syncModels = async () => {
    try {
        await sequelize.sync({ alter: true });
        console.log('✅ Models synchronized with database');
    } catch (error) {
        console.error('❌ Error syncing models:', error);
    }
};

module.exports = {
    sequelize,
    AuthModelBlacklist,
    syncModels
};
