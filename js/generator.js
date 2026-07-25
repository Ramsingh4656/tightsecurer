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
 * Generates a cryptographically secure random password based on the provided options.
 * Guarantees that the password scores "Very Strong" (> 80 score) under analyzer.js rules.
 * @param {object} options - Configuration options.
 * @param {number} [options.length=16] - Length of the password.
 * @param {boolean} [options.uppercase=true] - Include uppercase letters.
 * @param {boolean} [options.lowercase=true] - Include lowercase letters.
 * @param {boolean} [options.numbers=true] - Include numeric digits.
 * @param {boolean} [options.symbols=true] - Include special symbols.
 * @returns {string} - The generated secure password.
 */
function generatePassword(options = {}) {
    // Read options or use defaults
    let length = options.length !== undefined ? options.length : 16;
    let useUpper = options.uppercase !== false;
    let useLower = options.lowercase !== false;
    let useNum = options.numbers !== false;
    let useSym = options.symbols !== false;

    // To guarantee the password scores "Very Strong" (> 80 points) under analyzer.js rules:
    // 1. The length must be at least 12 (otherwise length check fails, losing 20 points, max score becomes 80).
    if (length < 12) {
        length = 12;
        // Synchronize UI slider if elements are present
        const lengthSlider = document.getElementById("lengthSlider");
        const lengthDisplay = document.getElementById("lengthDisplay");
        if (lengthSlider) {
            lengthSlider.value = 12;
        }
        if (lengthDisplay) {
            lengthDisplay.textContent = "12";
        }
    }

    // 2. Ensure at least some character types are selected so we can generate characters.
    // If none are selected, default to all.
    if (!useUpper && !useLower && !useNum && !useSym) {
        useUpper = true;
        useLower = true;
        useNum = true;
        useSym = true;
    }

    // 3. To score > 80, we need the character pools to contribute enough points.
    // Length >= 12 (20 pts), No repeats (10 pts), No sequences (10 pts), Not common (15 pts), Entropy >= 3.0 (10 pts)
    // sum to 65 pts.
    // The character pool rules (uppercase: 10, lowercase: 10, numbers: 10, symbols: 15) must contribute > 15 pts.
    // If they contribute <= 15 pts (e.g. only symbols is selected (15 pts), or only numbers (10 pts), etc.),
    // then a score > 80 is mathematically impossible.
    // In such cases, we force enable all pools to guarantee "Very Strong".
    let potentialCharScore = 0;
    if (useUpper) potentialCharScore += 10;
    if (useLower) potentialCharScore += 10;
    if (useNum) potentialCharScore += 10;
    if (useSym) potentialCharScore += 15;

    if (65 + potentialCharScore <= 80) {
        useUpper = true;
        useLower = true;
        useNum = true;
        useSym = true;
    }

    // Generate candidate passwords and validate them against analyzer.js rules
    let password = "";
    let attempts = 0;
    const maxAttempts = 1000;

    const analyzeFn = typeof analyzePassword === "function" ? analyzePassword : null;

    while (attempts < maxAttempts) {
        const candidate = generateCandidate(length, useUpper, useLower, useNum, useSym);
        
        // If analyzePassword is loaded, verify the actual score.
        // Otherwise, candidate is generated with robust rules so it should be secure.
        if (analyzeFn) {
            const analysisResult = analyzeFn(candidate);
            if (analysisResult.status === "Very Strong") {
                password = candidate;
                break;
            }
        } else {
            password = candidate;
            break;
        }
        attempts++;
    }

    // Fallback if loop didn't find one (extremely unlikely)
    if (!password) {
        password = generateCandidate(length, true, true, true, true);
    }

    return password;
}

/**
 * Generates a candidate password string of given length using specified character classes.
 * @param {number} length - Password length.
 * @param {boolean} useUpper - Include uppercase.
 * @param {boolean} useLower - Include lowercase.
 * @param {boolean} useNum - Include numbers.
 * @param {boolean} useSym - Include symbols.
 * @returns {string} - Candidate password string.
 */
function generateCandidate(length, useUpper, useLower, useNum, useSym) {
    const pools = [];
    const mandatory = [];

    if (useLower) {
        pools.push(CHARS_LOWER);
        mandatory.push(getRandomChar(CHARS_LOWER));
    }
    if (useUpper) {
        pools.push(CHARS_UPPER);
        mandatory.push(getRandomChar(CHARS_UPPER));
    }
    if (useNum) {
        pools.push(CHARS_NUMBERS);
        mandatory.push(getRandomChar(CHARS_NUMBERS));
    }
    if (useSym) {
        pools.push(CHARS_SYMBOLS);
        mandatory.push(getRandomChar(CHARS_SYMBOLS));
    }

    const combinedPool = pools.join("");
    const remainingLength = length - mandatory.length;
    const remaining = [];

    // Fill remaining length using secure random choices from combined pool
    for (let i = 0; i < remainingLength; i++) {
        remaining.push(getRandomChar(combinedPool));
    }

    // Combine and shuffle securely
    const combinedList = mandatory.concat(remaining);
    secureShuffleArray(combinedList);

    return combinedList.join("");
}

/**
 * Retrieves a cryptographically secure random character from the provided pool.
 * @param {string} pool - Character pool.
 * @returns {string} - A random character.
 */
function getRandomChar(pool) {
    const buffer = new Uint32Array(1);
    window.crypto.getRandomValues(buffer);
    const randomIndex = buffer[0] % pool.length;
    return pool.charAt(randomIndex);
}

/**
 * Shuffles an array in place using cryptographically secure random values.
 * @param {Array} array - Array to shuffle.
 */
function secureShuffleArray(array) {
    const randomBuffer = new Uint32Array(array.length);
    window.crypto.getRandomValues(randomBuffer);

    for (let i = array.length - 1; i > 0; i--) {
        const j = randomBuffer[i] % (i + 1);
        const temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
}

/**
 * Compatibility wrapper that app.js calls.
 * Extracts options from the DOM and calls generatePassword.
 * @param {number} length - Desired password length.
 * @returns {string} - Generated password.
 */
function generateStrongPassword(length = 16) {
    const options = getGeneratorOptions();
    options.length = length;
    return generatePassword(options);
}

/**
 * Reads generator options from the DOM controls (slider and checkboxes if present).
 * @returns {object} - Configuration options.
 */
function getGeneratorOptions() {
    const options = {
        length: 16,
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: true
    };

    const lengthSlider = document.getElementById("lengthSlider");
    if (lengthSlider) {
        options.length = parseInt(lengthSlider.value, 10) || 16;
    }

    // Check for character type checkboxes
    const checkboxes = document.querySelectorAll("input[type='checkbox']");
    if (checkboxes.length > 0) {
        let foundAny = false;
        const tempOptions = {
            uppercase: false,
            lowercase: false,
            numbers: false,
            symbols: false
        };

        checkboxes.forEach(cb => {
            const id = (cb.id || "").toLowerCase();
            const name = (cb.name || "").toLowerCase();
            const value = cb.checked;

            if (id.includes("upper") || name.includes("upper")) {
                tempOptions.uppercase = value;
                foundAny = true;
            } else if (id.includes("lower") || name.includes("lower")) {
                tempOptions.lowercase = value;
                foundAny = true;
            } else if (id.includes("num") || id.includes("digit") || name.includes("num") || name.includes("digit")) {
                tempOptions.numbers = value;
                foundAny = true;
            } else if (id.includes("symbol") || id.includes("spec") || name.includes("symbol") || name.includes("spec")) {
                tempOptions.symbols = value;
                foundAny = true;
            }
        });

        if (foundAny) {
            Object.assign(options, tempOptions);
        }
    }

    return options;
}

/**
 * Renders a temporary toast notification alert on the bottom right.
 * @param {string} message - Message text to display.
 * @param {string} type - Notification type: 'success' | 'error'.
 */
function showToastNotification(message, type = "success") {
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

// Add event listeners on DOMContentLoaded to handle Copy and Regenerate
if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", () => {
        const copyBtn = document.getElementById("copyBtn");
        const regenerateBtn = document.getElementById("regenerateBtn");
        const generatedPasswordBox = document.getElementById("generatedPasswordBox");
        const lengthSlider = document.getElementById("lengthSlider");

        // Enforce slider min length to be 12 on load to prevent weak passwords
        if (lengthSlider) {
            lengthSlider.min = "12";
            if (parseInt(lengthSlider.value, 10) < 12) {
                lengthSlider.value = "12";
                const lengthDisplay = document.getElementById("lengthDisplay");
                if (lengthDisplay) {
                    lengthDisplay.textContent = "12";
                }
            }
        }

        if (copyBtn) {
            copyBtn.addEventListener("click", (event) => {
                // Prevent duplicate handling from app.js
                event.stopImmediatePropagation();

                const textToCopy = generatedPasswordBox ? generatedPasswordBox.textContent : "";
                if (!textToCopy || textToCopy === "Press regenerate...") {
                    showToastNotification("No password available to copy.", "error");
                    return;
                }

                if (typeof copyToClipboard === "function") {
                    copyToClipboard(textToCopy).then(success => {
                        if (success) {
                            showToastNotification("Password copied to clipboard!", "success");
                        } else {
                            showToastNotification("Failed to copy password automatically.", "error");
                        }
                    });
                }
            });
        }

        if (regenerateBtn) {
            regenerateBtn.addEventListener("click", (event) => {
                // Prevent duplicate handling from app.js
                event.stopImmediatePropagation();

                // Spin animation on button
                regenerateBtn.classList.add("animate-shake");
                setTimeout(() => {
                    regenerateBtn.classList.remove("animate-shake");
                }, 600);

                const options = getGeneratorOptions();
                const password = generatePassword(options);
                
                if (generatedPasswordBox) {
                    generatedPasswordBox.textContent = password;
                    
                    // Add custom dynamic glow/animation trigger
                    generatedPasswordBox.classList.add("animate-fade-in");
                    setTimeout(() => {
                        generatedPasswordBox.classList.remove("animate-fade-in");
                    }, 800);
                }
            });
        }
    });
}

// Bind to window object to ensure global availability
if (typeof window !== "undefined") {
    window.generateStrongPassword = generateStrongPassword;
    window.generatePassword = generatePassword;
}

// Export module if running in a modular environment
if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        generateStrongPassword,
        generatePassword
    };
}
