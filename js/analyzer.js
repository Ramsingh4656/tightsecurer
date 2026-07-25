/**
 * Core analysis and strength rules for the Password Security Assistant.
 * Follows camelCase naming convention.
 * Evaluates password strength against 9 metrics using a 100-point scoring system.
 */

// A small array of highly common passwords for fallback/direct check
const COMMON_PASSWORDS_LIST = [
    "123456",
    "password",
    "qwerty",
    "admin",
    "welcome"
];

/**
 * Scans passwords to identify forward or reverse keyboard runs of 3 or more keys.
 * Matches rows: qwertyuiop, asdfghjkl, zxcvbnm, and 1234567890.
 * @param {string} password - The password to scan.
 * @returns {boolean} - True if a keyboard pattern of length 3+ is found.
 */
function hasKeyboardPatternLocal(password) {
    const keyboardRows = [
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890"
    ];
    const lowerPassword = password.toLowerCase();

    for (const row of keyboardRows) {
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
 * Checks for alphabetical (abc, cba) or numerical (123, 321) runs of length 3 in the password.
 * @param {string} password - The password to check.
 * @returns {boolean} - True if a sequential run of length 3 is found, false otherwise.
 */
function hasSequentialCharacters(password) {
    const lowerPassword = password.toLowerCase();
    for (let i = 0; i < lowerPassword.length - 2; i++) {
        const char1 = lowerPassword.charCodeAt(i);
        const char2 = lowerPassword.charCodeAt(i + 1);
        const char3 = lowerPassword.charCodeAt(i + 2);

        // Ensure all three characters are lowercase letters (97-122) or all three are digits (48-57)
        const isWord1 = (char1 >= 97 && char1 <= 122);
        const isWord2 = (char2 >= 97 && char2 <= 122);
        const isWord3 = (char3 >= 97 && char3 <= 122);

        const isDigit1 = (char1 >= 48 && char1 <= 57);
        const isDigit2 = (char2 >= 48 && char2 <= 57);
        const isDigit3 = (char3 >= 48 && char3 <= 57);

        if ((isWord1 && isWord2 && isWord3) || (isDigit1 && isDigit2 && isDigit3)) {
            // Ascending sequence (e.g., abc, 123)
            if (char2 === char1 + 1 && char3 === char1 + 2) {
                return true;
            }
            // Descending sequence (e.g., cba, 321)
            if (char2 === char1 - 1 && char3 === char1 - 2) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Calculates the Shannon Entropy of a password string.
 * Formula: H = -sum(p_i * log2(p_i))
 * @param {string} str - The password string.
 * @returns {number} - Calculated Shannon entropy value rounded to 2 decimal places.
 */
function calculateEntropy(str) {
    if (!str) return 0;
    const len = str.length;
    const frequencies = {};

    for (let i = 0; i < len; i++) {
        const char = str[i];
        frequencies[char] = (frequencies[char] || 0) + 1;
    }

    let entropy = 0;
    for (const char in frequencies) {
        const p = frequencies[char] / len;
        entropy -= p * Math.log2(p);
    }

    return parseFloat(entropy.toFixed(2));
}

/**
 * Analyzes the given password against the 9 scoring rules and compiles
 * scores, weaknesses, suggestions, and strength status.
 * @param {string} password - The password to analyze.
 * @returns {object} - Analysis results including score, status, weaknesses, suggestions, passedRules, and entropy.
 */
function analyzePassword(password) {
    // If no password is provided, return empty defaults
    if (!password) {
        return {
            score: 0,
            status: "Weak",
            weaknesses: ["Password cannot be empty"],
            suggestions: ["Please enter a password to start the analysis."],
            passedRules: {
                length: false,
                uppercase: false,
                lowercase: false,
                number: false,
                symbol: false,
                noRepeats: false,
                noSequences: false,
                notCommon: false,
                entropy: false
            },
            entropy: 0
        };
    }

    const weaknesses = [];
    const suggestions = [];
    const passedRules = {};

    // 1. Length check: 12+ characters (20 points)
    const isLongEnough = password.length >= 12;
    passedRules.length = isLongEnough;
    if (!isLongEnough) {
        weaknesses.push("Password is too short (under 12 characters)");
        suggestions.push("Make the password at least 12 characters long to increase complexity.");
    }

    // 2. Uppercase check (10 points)
    const hasUppercase = /[A-Z]/.test(password);
    passedRules.uppercase = hasUppercase;
    if (!hasUppercase) {
        weaknesses.push("Missing uppercase letters");
        suggestions.push("Insert at least one capital letter (A-Z).");
    }

    // 3. Lowercase check (10 points)
    const hasLowercase = /[a-z]/.test(password);
    passedRules.lowercase = hasLowercase;
    if (!hasLowercase) {
        weaknesses.push("Missing lowercase letters");
        suggestions.push("Insert at least one small letter (a-z).");
    }

    // 4. Number check (10 points)
    const hasNumber = /[0-9]/.test(password);
    passedRules.number = hasNumber;
    if (!hasNumber) {
        weaknesses.push("Missing numbers");
        suggestions.push("Add at least one numerical digit (0-9).");
    }

    // 5. Symbol check (15 points)
    const hasSymbol = /[^A-Za-z0-9]/.test(password);
    passedRules.symbol = hasSymbol;
    if (!hasSymbol) {
        weaknesses.push("Missing special characters");
        suggestions.push("Include at least one symbol (e.g. !, @, #, $, %, &, *).");
    }

    // 6. No repeats check (10 points)
    const hasRepeats = /(.)\1/.test(password);
    passedRules.noRepeats = !hasRepeats;
    if (hasRepeats) {
        weaknesses.push("Contains consecutive identical characters");
        suggestions.push("Avoid consecutive repeated characters (e.g., 'aa', '55').");
    }

    // 7. No sequences check (10 points)
    const hasSeq = hasSequentialCharacters(password) || hasKeyboardPatternLocal(password);
    passedRules.noSequences = !hasSeq;
    if (hasSeq) {
        weaknesses.push("Contains sequential letters, numbers, or keyboard patterns");
        suggestions.push("Avoid using sequences of characters (e.g., '123', 'abc', 'qwe').");
    }

    // 8. Not common check (15 points)
    const lowerPassword = password.toLowerCase();
    let isCommon = COMMON_PASSWORDS_LIST.includes(lowerPassword);
    if (!isCommon && typeof isCommonPassword === "function") {
        isCommon = isCommonPassword(password);
    }
    passedRules.notCommon = !isCommon;
    if (isCommon) {
        weaknesses.push("Password matches a known common password");
        suggestions.push("Use a unique phrase instead of a highly common password.");
    }

    // 9. Entropy check (10 points)
    const entropyVal = calculateEntropy(password);
    const isEntropyGood = entropyVal >= 3.0;
    passedRules.entropy = isEntropyGood;
    if (!isEntropyGood) {
        weaknesses.push(`Low character randomness (Entropy: ${entropyVal} bits)`);
        suggestions.push("Vary the order of characters more unpredictably to increase entropy.");
    }

    // Calculate total score based on scoring rules
    let score = 0;
    if (passedRules.length) score += 20;
    if (passedRules.uppercase) score += 10;
    if (passedRules.lowercase) score += 10;
    if (passedRules.number) score += 10;
    if (passedRules.symbol) score += 15;
    if (passedRules.noRepeats) score += 10;
    if (passedRules.noSequences) score += 10;
    if (passedRules.notCommon) score += 15;
    if (passedRules.entropy) score += 10;

    // Cap score at 100 points
    score = Math.min(100, score);

    // Strength levels: 0-30 Weak, 31-60 Medium, 61-80 Strong, 81-100 Very Strong
    let status = "Weak";
    if (score > 80) {
        status = "Very Strong";
    } else if (score > 60) {
        status = "Strong";
    } else if (score > 30) {
        status = "Medium";
    }

    return {
        score,
        status,
        weaknesses,
        suggestions,
        passedRules,
        entropy: entropyVal
    };
}

// Bind to window object to ensure global availability
if (typeof window !== "undefined") {
    window.analyzePassword = analyzePassword;
}

// Add event listener to read the password from passwordInput when analyzeBtn is clicked
if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", () => {
        const analyzeBtn = document.getElementById("analyzeBtn");
        const passwordInput = document.getElementById("passwordInput");
        if (analyzeBtn && passwordInput) {
            analyzeBtn.addEventListener("click", () => {
                const password = passwordInput.value;
                analyzePassword(password);
            });
        }
    });
}

// Export module if running in a modular environment
if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        analyzePassword,
        hasKeyboardPatternLocal,
        hasSequentialCharacters,
        calculateEntropy
    };
}
