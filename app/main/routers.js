const authRouter = require('../api/v1/business/auth/auth_router');

const addRouters = (router) => {
    router.route('/health').get((req, res) => {
        return res.status(200).json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            service: 'auth-ms',
            version: process.env.npm_package_version || '1.0.0'
        });
    });

    router.use('/auth', authRouter);

    return router;
};

module.exports = addRouters;
