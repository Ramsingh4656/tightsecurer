/**
 * Utility functions for the Password Security Assistant.
 * Follows camelCase naming convention.
 */

/**
 * Query selector shortcut.
 * @param {string} selector - CSS selector.
 * @returns {Element|null} - Selected DOM element.
 */
function $(selector) {
    return document.querySelector(selector);
}

/**
 * Query selector all shortcut.
 * @param {string} selector - CSS selector.
 * @returns {NodeList} - Selected DOM elements.
 */
function $$(selector) {
    return document.querySelectorAll(selector);
}

/**
 * Debounces a function.
 * @param {Function} func - Function to debounce.
 * @param {number} wait - Delay in milliseconds.
 * @returns {Function} - Debounced function.
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

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

/**
 * Renders a temporary toast notification alert on the bottom right.
 * @param {string} message - Message text to display.
 * @param {string} type - Notification type: 'success' | 'error'.
 */
function showToast(message, type = "success") {
    const toastContainer = document.getElementById("toastContainer");
    if (!toastContainer) return;

    const toast = document.createElement("div");
    toast.className = `toast toast-${type} animate-slide-in-right`;

    // SVGs for toast status icon
    const successSvg = `
        <svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="20 6 9 17 4 12"></polyline>
        </svg>
    `;
    const errorSvg = `
        <svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
        </svg>
    `;

    toast.innerHTML = `
        ${type === "success" ? successSvg : errorSvg}
        <span>${message}</span>
    `;

    toastContainer.appendChild(toast);

    // Slide out and destroy toast after delay
    setTimeout(() => {
        toast.classList.remove("animate-slide-in-right");
        toast.classList.add("animate-slide-out-right");
        toast.addEventListener("animationend", () => {
            toast.remove();
        });
    }, 2800);
}

// Bind to window object to ensure global availability
if (typeof window !== "undefined") {
    window.$ = $;
    window.$$ = $$;
    window.debounce = debounce;
    window.showToast = showToast;
    window.isCommonPassword = isCommonPassword;
    window.hasKeyboardPattern = hasKeyboardPattern;
    window.calculateShannonEntropy = calculateShannonEntropy;
    window.copyToClipboard = copyToClipboard;
}

// Export module if running in a modular environment
if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        $,
        $$,
        debounce,
        showToast,
        isCommonPassword,
        hasKeyboardPattern,
        calculateShannonEntropy,
        copyToClipboard
    };
}
