/**
 * Cryptographically secure password generator for the Password Security Assistant.
 * Follows camelCase naming convention.
 */

// Define character pools for generation
const CHARS_LOWER = "abcdefghijklmnopqrstuvwxyz";
const CHARS_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const CHARS_NUMBERS = "0123456789";
const CHARS_SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?~";

/**
 * Generates a cryptographically secure random password of the specified length.
 * Ensures the password contains at least one lowercase, uppercase, number, and symbol.
 * @param {number} length - The desired password length.
 * @returns {string} - The generated secure password.
 */
function generateStrongPassword(length = 16) {
    // Ensure length is within reasonable bounds
    const pwdLength = Math.max(8, Math.min(64, length));

    // Choose one mandatory character from each set to guarantee strength
    const mandatoryChars = [
        getRandomChar(CHARS_LOWER),
        getRandomChar(CHARS_UPPER),
        getRandomChar(CHARS_NUMBERS),
        getRandomChar(CHARS_SYMBOLS)
    ];

    // Combine all pools for the remaining characters
    const allPool = CHARS_LOWER + CHARS_UPPER + CHARS_NUMBERS + CHARS_SYMBOLS;
    const remainingLength = pwdLength - mandatoryChars.length;
    const remainingChars = [];

    for (let i = 0; i < remainingLength; i++) {
        remainingChars.push(getRandomChar(allPool));
    }

    // Merge and shuffle all characters using Fisher-Yates secure shuffle
    const passwordArray = mandatoryChars.concat(remainingChars);
    secureShuffleArray(passwordArray);

    return passwordArray.join("");
}

/**
 * Helper function to get a single random character from a character pool using window.crypto.
 * @param {string} pool - The string pool of characters.
 * @returns {string} - A random character from the pool.
 */
function getRandomChar(pool) {
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    const randomIndex = array[0] % pool.length;
    return pool.charAt(randomIndex);
}

/**
 * Shuffles an array in place using cryptographically secure random numbers.
 * @param {Array} array - The array to shuffle.
 */
function secureShuffleArray(array) {
    const randomBuffer = new Uint32Array(array.length);
    window.crypto.getRandomValues(randomBuffer);

    for (let i = array.length - 1; i > 0; i--) {
        // Map secure random number to range [0, i]
        const j = randomBuffer[i] % (i + 1);
        
        // Swap elements
        const temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
}
