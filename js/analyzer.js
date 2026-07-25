/**
 * Core analysis and strength rules for the Password Security Assistant.
 * Follows camelCase naming convention.
 * Depends on functions in utils.js.
 */

/**
 * Analyzes the given password against the 9 scoring rules and compiles
 * scores, weaknesses, suggestions, and strength status.
 * @param {string} password - The password to analyze.
 * @returns {object} - Analysis results including score, status, weaknesses, suggestions, and detail checks.
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
            }
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
    // Common symbols: !@#$%^&*()_+-=[]{}|;':",./<>?~`
    const hasSymbol = /[^A-Za-z0-9]/.test(password);
    passedRules.symbol = hasSymbol;
    if (!hasSymbol) {
        weaknesses.push("Missing special characters");
        suggestions.push("Include at least one symbol (e.g. !, @, #, $, %, &, *).");
    }

    // 6. No repeats check (10 points)
    // Looks for consecutive repeating characters (e.g., "aa", "11", "!!")
    const hasRepeats = /(.)\1/.test(password);
    passedRules.noRepeats = !hasRepeats;
    if (hasRepeats) {
        weaknesses.push("Contains consecutive identical characters");
        suggestions.push("Avoid consecutive repeated characters (e.g., 'aa', '55').");
    }

    // 7. No sequences check (10 points)
    // Check for numerical or alphabetical sequences (e.g., "abc", "123", "321", "cba")
    // Also checks keyboard rows via utility function
    let hasSequence = false;
    
    // Check alphabetical and numeric sequences (length 3)
    const lowerPassword = password.toLowerCase();
    for (let i = 0; i < lowerPassword.length - 2; i++) {
        const char1 = lowerPassword.charCodeAt(i);
        const char2 = lowerPassword.charCodeAt(i + 1);
        const char3 = lowerPassword.charCodeAt(i + 2);

        // Ascending sequence (e.g. a-b-c, 1-2-3)
        if (char2 === char1 + 1 && char3 === char1 + 2) {
            // Ensure they are actually letters or digits
            const isWord = (char1 >= 97 && char1 <= 122);
            const isDigit = (char1 >= 48 && char1 <= 57);
            if (isWord || isDigit) {
                hasSequence = true;
                break;
            }
        }
        // Descending sequence (e.g. c-b-a, 3-2-1)
        if (char2 === char1 - 1 && char3 === char1 - 2) {
            const isWord = (char1 >= 97 && char1 <= 122);
            const isDigit = (char1 >= 48 && char1 <= 57);
            if (isWord || isDigit) {
                hasSequence = true;
                break;
            }
        }
    }

    // Also check keyboard patterns
    if (!hasSequence && typeof hasKeyboardPattern === "function") {
        hasSequence = hasKeyboardPattern(password);
    }

    passedRules.noSequences = !hasSequence;
    if (hasSequence) {
        weaknesses.push("Contains sequential letters, numbers, or keyboard patterns");
        suggestions.push("Avoid using sequences of characters (e.g., '123', 'abc', 'qwe').");
    }

    // 8. Not common check (15 points)
    let isCommon = false;
    if (typeof isCommonPassword === "function") {
        isCommon = isCommonPassword(password);
    }
    passedRules.notCommon = !isCommon;
    if (isCommon) {
        weaknesses.push("Password matches a known common password");
        suggestions.push("Use a unique phrase instead of a highly common password.");
    }

    // 9. Entropy check (10 points)
    // Shannon entropy threshold >= 3.0 bits for password randomness
    let entropyVal = 0;
    if (typeof calculateShannonEntropy === "function") {
        entropyVal = calculateShannonEntropy(password);
    }
    const isEntropyGood = entropyVal >= 3.0;
    passedRules.entropy = isEntropyGood;
    if (!isEntropyGood) {
        weaknesses.push(`Low character randomness (Entropy: ${entropyVal} bits)`);
        suggestions.push("Vary the order of characters more unpredictably to increase entropy.");
    }

    // Calculate score based on scoring rules
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
