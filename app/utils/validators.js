/**
 * Validators - Validation functions
 *
 * This module contains validation functions for email, password and name
 */

/**
 * Validates if an email is valid
 * @param {string} email - Email to be validated
 * @returns {boolean} true if valid, false otherwise
 */
const validateEmail = (email) => {
    if (!email || typeof email !== 'string') {
        return false;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email.trim());
};

/**
 * Validates if a password is valid
 * @param {string} password - Password to be validated
 * @returns {boolean} true if valid, false otherwise
 */
const validatePassword = (password) => {
    if (!password || typeof password !== 'string') {
        return false;
    }

    // Minimum 8 characters, including uppercase, lowercase and numbers
    const minLength = password.length >= 8;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);

    return minLength && hasUppercase && hasLowercase && hasNumbers;
};

/**
 * Validates if a name is valid
 * @param {string} name - Name to be validated
 * @returns {boolean} true if valid, false otherwise
 */
const validateName = (name) => {
    if (!name || typeof name !== 'string') {
        return false;
    }

    const trimmedName = name.trim();

    // Minimum 2 characters, maximum 100 characters
    if (trimmedName.length < 2 || trimmedName.length > 100) {
        return false;
    }

    // Must contain only letters, spaces, hyphens and accents
    const nameRegex = /^[a-zA-ZÀ-ÿ\s\-']+$/;
    return nameRegex.test(trimmedName);
};

module.exports = {
    validateEmail,
    validatePassword,
    validateName
};
