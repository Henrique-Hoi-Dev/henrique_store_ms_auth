const schedule = require('node-schedule');
const { TokenBlacklist } = require('../models');
const logger = require('../app/utils/logger');

/**
 * Clean up expired tokens from blacklist
 */
const cleanupExpiredTokens = async () => {
    try {
        const result = await TokenBlacklist.destroy({
            where: {
                expiresAt: {
                    [require('sequelize').Op.lt]: new Date()
                }
            }
        });

        if (result > 0) {
            logger.info(`Cleaned up ${result} expired tokens from blacklist`);
        }
    } catch (error) {
        logger.error('Error cleaning up expired tokens:', error);
    }
};

/**
 * Schedule token cleanup job
 * Runs every hour
 */
const scheduleTokenCleanup = () => {
    // Run cleanup every hour
    schedule.scheduleJob('0 * * * *', cleanupExpiredTokens);

    // Also run cleanup on startup
    cleanupExpiredTokens();

    logger.info('Token cleanup job scheduled');
};

module.exports = {
    cleanupExpiredTokens,
    scheduleTokenCleanup
};
