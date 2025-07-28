const { validateRequest } = require('./joi_middleware');

module.exports = (schema) => validateRequest(schema);
