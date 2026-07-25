/**
 * Statistics and Tips Manager for the Password Security Assistant.
 * Handles the display of character composition breakdown, Shannon entropy, 
 * and context-aware security tips.
 * Follows camelCase naming convention.
 */

// Dynamic security tips database
const SECURITY_TIPS = [
    {
        id: "length",
        rule: "length",
        text: "Longer passwords are exponentially harder to crack. Aim for at least 12–16 characters."
    },
    {
        id: "uppercase",
        rule: "uppercase",
        text: "Capital letters disrupt standard lowercase dictionary attacks. Mix in A-Z characters."
    },
    {
        id: "lowercase",
        rule: "lowercase",
        text: "Lowercase letters form the foundation of most passwords. Ensure they are part of your pattern."
    },
    {
        id: "number",
        rule: "number",
        text: "Digits increase the character space. Scatter numbers (0-9) throughout the password, not just at the end."
    },
    {
        id: "symbol",
        rule: "symbol",
        text: "Special characters (like $, !, @, *) vastly increase complexity against automated tools."
    },
    {
        id: "repeats",
        rule: "noRepeats",
        text: "Avoid repeating characters (e.g. 'aaa' or '11'). They reduce unique patterns and lower password entropy."
    },
    {
        id: "sequences",
        rule: "noSequences",
        text: "Sequential characters (like 'abc', '123' or keyboard patterns 'qwe') are easily guessed by dictionary tools."
    },
    {
        id: "common",
        rule: "notCommon",
        text: "Avoid common words, phrases, or names. Unique or randomized word combinations make the best passphrases."
    },
    {
        id: "entropy",
        rule: "entropy",
        text: "Vary the character types and avoid predictable structures to increase mathematical randomness (Shannon Entropy)."
    }
];

// General tips when all rules pass or no password is typed
const GENERAL_TIPS = [
    "Never reuse passwords across different accounts. If one gets breached, others remain secure.",
    "Use a trusted, offline-first password manager to store and manage complex credentials.",
    "Enable Multi-Factor Authentication (MFA/2FA) on critical accounts whenever available.",
    "Change passwords immediately if you suspect or receive alerts of a service breach.",
    "A randomized passphrase of 4-5 unrelated words can be extremely secure and easier to remember than random symbols."
];

/**
 * Gets a relevant security tip based on failed rules in the analysis result,
 * or returns a random general tip.
 * @param {object} analysisResult - The result from analyzePassword.
 * @returns {string} - A security tip message.
 */
function getSecurityTip(analysisResult) {
    if (analysisResult && analysisResult.passedRules) {
        // Find failed rules
        const failedRules = [];
        for (const rule in analysisResult.passedRules) {
            if (!analysisResult.passedRules[rule]) {
                failedRules.push(rule);
            }
        }
        
        // If there are failed rules, prioritize tips addressing those failures
        if (failedRules.length > 0) {
            // Find tip matching one of the failed rules (pick one randomly from failed ones)
            const matchedTips = SECURITY_TIPS.filter(tip => failedRules.includes(tip.rule));
            if (matchedTips.length > 0) {
                const randomIndex = Math.floor(Math.random() * matchedTips.length);
                return matchedTips[randomIndex].text;
            }
        }
    }
    
    // Default fallback: pick a random general tip
    const randomIndex = Math.floor(Math.random() * GENERAL_TIPS.length);
    return GENERAL_TIPS[randomIndex];
}

/**
 * Renders the statistics card and security tips card inside statsSection.
 * @param {string} password - The password string.
 * @param {object} analysisResult - The analysis results object.
 */
function updateStatistics(password, analysisResult) {
    const statsContainer = document.getElementById("statsSection");
    if (!statsContainer) return;

    // Default calculations if no password or analysis is available
    const hasPassword = !!password;
    const length = password ? password.length : 0;
    const uppercaseCount = password ? (password.match(/[A-Z]/g) || []).length : 0;
    const lowercaseCount = password ? (password.match(/[a-z]/g) || []).length : 0;
    const numberCount = password ? (password.match(/[0-9]/g) || []).length : 0;
    const specialCount = password ? (password.match(/[^A-Za-z0-9]/g) || []).length : 0;

    const score = analysisResult ? analysisResult.score : 0;
    const entropy = analysisResult ? analysisResult.entropy : 0.00;
    const status = analysisResult ? analysisResult.status : "Weak";
    const strengthPercentage = score; // Out of 100

    // Set colors according to strength status
    let statusClass = "danger-text";
    if (status === "Very Strong") {
        statusClass = "success-text";
    } else if (status === "Strong") {
        statusClass = "info-text";
    } else if (status === "Medium") {
        statusClass = "warning-text";
    }

    // Pick a relevant security tip
    const securityTip = getSecurityTip(analysisResult);

    // Calculate composition percentages for the bars
    const uppercasePercent = length > 0 ? (uppercaseCount / length) * 100 : 0;
    const lowercasePercent = length > 0 ? (lowercaseCount / length) * 100 : 0;
    const numberPercent = length > 0 ? (numberCount / length) * 100 : 0;
    const specialPercent = length > 0 ? (specialCount / length) * 100 : 0;

    // Shannon entropy bar percent (scaled against 8 bits)
    const entropyPercent = Math.min(100, (entropy / 8) * 100);
    // Length bar percent (scaled against 24 chars)
    const lengthPercent = Math.min(100, (length / 24) * 100);

    // Render HTML content
    statsContainer.innerHTML = `
        <div class="stats-card animate-fade-in">
            <h3 class="stats-title">Password Statistics</h3>
            
            ${hasPassword ? `
                <div class="stats-grid">
                    <div class="stat-box">
                        <span class="stat-value ${statusClass}">${score}</span>
                        <span class="stat-label">Quality Score</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-value ${statusClass}">${strengthPercentage}%</span>
                        <span class="stat-label">Strength</span>
                    </div>
                </div>

                <div class="distribution-section">
                    <h4 class="sub-title">Character Composition</h4>
                    
                    <div class="dist-row">
                        <div class="dist-label-container">
                            <span class="dist-label-tag" style="background: rgba(255, 255, 255, 0.05); color: var(--text-primary);">Length</span>
                            <span class="dist-count">${length} / 24+ chars</span>
                        </div>
                        <div class="dist-bar-bg">
                            <div class="dist-bar-fill" style="width: ${lengthPercent}%; background-color: var(--primary-blue);"></div>
                        </div>
                    </div>

                    <div class="dist-row">
                        <div class="dist-label-container">
                            <span class="dist-label-tag uppercase-tag" style="background: rgba(59, 130, 246, 0.12); color: #60A5FA;">Uppercase Letters</span>
                            <span class="dist-count">${uppercaseCount} (${Math.round(uppercasePercent)}%)</span>
                        </div>
                        <div class="dist-bar-bg">
                            <div class="dist-bar-fill" style="width: ${uppercasePercent}%; background-color: var(--info-blue);"></div>
                        </div>
                    </div>

                    <div class="dist-row">
                        <div class="dist-label-container">
                            <span class="dist-label-tag lowercase-tag" style="background: rgba(59, 130, 246, 0.12); color: #60A5FA;">Lowercase Letters</span>
                            <span class="dist-count">${lowercaseCount} (${Math.round(lowercasePercent)}%)</span>
                        </div>
                        <div class="dist-bar-bg">
                            <div class="dist-bar-fill" style="width: ${lowercasePercent}%; background-color: var(--info-blue);"></div>
                        </div>
                    </div>

                    <div class="dist-row">
                        <div class="dist-label-container">
                            <span class="dist-label-tag number-tag" style="background: rgba(250, 204, 21, 0.12); color: #FDE047;">Numbers</span>
                            <span class="dist-count">${numberCount} (${Math.round(numberPercent)}%)</span>
                        </div>
                        <div class="dist-bar-bg">
                            <div class="dist-bar-fill" style="width: ${numberPercent}%; background-color: var(--warning-yellow);"></div>
                        </div>
                    </div>

                    <div class="dist-row">
                        <div class="dist-label-container">
                            <span class="dist-label-tag special-tag" style="background: rgba(34, 197, 94, 0.12); color: #4ADE80;">Special Characters</span>
                            <span class="dist-count">${specialCount} (${Math.round(specialPercent)}%)</span>
                        </div>
                        <div class="dist-bar-bg">
                            <div class="dist-bar-fill" style="width: ${specialPercent}%; background-color: var(--success-green);"></div>
                        </div>
                    </div>

                    <div class="dist-row">
                        <div class="dist-label-container">
                            <span class="dist-label-tag entropy-tag" style="background: rgba(168, 85, 247, 0.12); color: #C084FC;">Shannon Entropy</span>
                            <span class="dist-count">${entropy} bits</span>
                        </div>
                        <div class="dist-bar-bg">
                            <div class="dist-bar-fill" style="width: ${entropyPercent}%; background-color: #A855F7;"></div>
                        </div>
                    </div>
                </div>
            ` : `
                <p class="card-description" style="text-align: center; margin: 2rem 0; font-style: italic; color: var(--text-muted);">
                    Enter or generate a password to display character breakdown and security statistics.
                </p>
            `}
        </div>

        <div class="stats-card animate-fade-in" style="margin-top: 1.5rem;">
            <h3 class="stats-title" style="font-size: 1.1rem; margin-bottom: 0.75rem;">Password Security Tip</h3>
            <div id="securityTipContainer" style="min-height: 60px; display: flex; flex-direction: column; justify-content: center;">
                <p id="securityTipText" style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5; font-style: italic;">
                    ${securityTip}
                </p>
            </div>
        </div>
    `;
}

/**
 * Legacy compatibility functions for app.js (if they are called directly).
 */
function renderStatistics() {
    updateStatistics("", null);
}

function trackAnalysis(analysisResult) {
    // Falls back to render metrics of whatever password is currently in passwordInput
    const passwordInput = document.getElementById("passwordInput");
    const password = passwordInput ? passwordInput.value : "";
    updateStatistics(password, analysisResult);
}

function resetStatistics() {
    renderStatistics();
}

// Bind to window object to ensure global availability
if (typeof window !== "undefined") {
    window.updateStatistics = updateStatistics;
    window.renderStatistics = renderStatistics;
    window.trackAnalysis = trackAnalysis;
    window.resetStatistics = resetStatistics;
}

// Export module if running in a modular environment
if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        updateStatistics,
        renderStatistics,
        trackAnalysis,
        resetStatistics
    };
}
