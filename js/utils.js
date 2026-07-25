/**
 * Utility functions for the Password Security Assistant.
 * Follows camelCase naming convention.
 */

// A list of the most common passwords for offline checks
const COMMON_PASSWORDS = [
    "123", "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
    "password", "qwerty", "111111", "football", "iloveyou", "princess", "admin", 
    "letmein", "sunshine", "charlie", "password123", "monkey", "welcome", "shadow", 
    "login", "secret", "trustnoone", "password123!", "pass123", "admin123", "root", 
    "oracle"
];

// QWERTY keyboard rows for sequence checking
const KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890"
];

/**
 * Checks if the password exists in the list of common passwords.
 * @param {string} password - The password to check.
 * @returns {boolean} - True if password is common, false otherwise.
 */
function isCommonPassword(password) {
    if (!password) return false;
    const lowerPassword = password.toLowerCase();
    return COMMON_PASSWORDS.includes(lowerPassword);
}

/**
 * Checks if the password contains any continuous horizontal keyboard sequences of 3 or more keys.
 * @param {string} password - The password to check.
 * @returns {boolean} - True if a keyboard pattern of length 3+ is found.
 */
function hasKeyboardPattern(password) {
    if (!password || password.length < 3) return false;
    const lowerPassword = password.toLowerCase();

    for (const row of KEYBOARD_ROWS) {
        // Forward check
        for (let i = 0; i <= row.length - 3; i++) {
            const seq = row.substring(i, i + 3);
            if (lowerPassword.includes(seq)) {
                return true;
            }
        }
        // Reverse check
        const reversedRow = row.split("").reverse().join("");
        for (let i = 0; i <= reversedRow.length - 3; i++) {
            const seq = reversedRow.substring(i, i + 3);
            if (lowerPassword.includes(seq)) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Calculates the Shannon Entropy of a password.
 * Formula: H = -sum(p_i * log2(p_i))
 * @param {string} password - The password string.
 * @returns {number} - Calculated Shannon entropy value.
 */
function calculateShannonEntropy(password) {
    if (!password) return 0;
    const len = password.length;
    const frequencies = {};

    // Calculate frequencies of each character
    for (let i = 0; i < len; i++) {
        const char = password[i];
        frequencies[char] = (frequencies[char] || 0) + 1;
    }

    // Calculate Shannon entropy
    let entropy = 0;
    for (const char in frequencies) {
        const p = frequencies[char] / len;
        entropy -= p * Math.log2(p);
    }

    return parseFloat(entropy.toFixed(2));
}

/**
 * Copies a given text to the system clipboard.
 * @param {string} text - The text to copy.
 * @returns {Promise<boolean>} - Resolves to true if successful, false otherwise.
 */
async function copyToClipboard(text) {
    if (!navigator.clipboard) {
        // Fallback for older browsers
        try {
            const textarea = document.createElement("textarea");
            textarea.value = text;
            textarea.style.position = "fixed"; // Avoid scrolling to bottom
            document.body.appendChild(textarea);
            textarea.focus();
            textarea.select();
            const successful = document.execCommand("copy");
            document.body.removeChild(textarea);
            return successful;
        } catch (err) {
            console.error("Fallback copy failed:", err);
            return false;
        }
    }

    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (err) {
        console.error("Async clipboard write failed:", err);
        return false;
    }
}
