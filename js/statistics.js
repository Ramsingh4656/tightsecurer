/**
 * Statistics manager for the Password Security Assistant.
 * Uses localStorage to persist data across page reloads.
 * Follows camelCase naming convention.
 */

const STATS_STORAGE_KEY = "password_security_assistant_stats";

// Default empty stats state
const DEFAULT_STATS = {
    totalAnalyzed: 0,
    totalScore: 0,
    strengthDistribution: {
        "Weak": 0,
        "Medium": 0,
        "Strong": 0,
        "Very Strong": 0
    },
    weaknessCounts: {
        "length": 0,
        "uppercase": 0,
        "lowercase": 0,
        "number": 0,
        "symbol": 0,
        "noRepeats": 0,
        "noSequences": 0,
        "notCommon": 0,
        "entropy": 0
    }
};

/**
 * Loads statistics from localStorage.
 * @returns {object} - The statistics object.
 */
function loadStatistics() {
    try {
        const stored = localStorage.getItem(STATS_STORAGE_KEY);
        if (stored) {
            const parsed = JSON.parse(stored);
            // Ensure schema matches in case of changes
            return {
                ...DEFAULT_STATS,
                ...parsed,
                strengthDistribution: {
                    ...DEFAULT_STATS.strengthDistribution,
                    ...(parsed.strengthDistribution || {})
                },
                weaknessCounts: {
                    ...DEFAULT_STATS.weaknessCounts,
                    ...(parsed.weaknessCounts || {})
                }
            };
        }
    } catch (e) {
        console.error("Failed to load statistics from localStorage", e);
    }
    return JSON.parse(JSON.stringify(DEFAULT_STATS));
}

/**
 * Saves statistics to localStorage.
 * @param {object} stats - The statistics object to save.
 */
function saveStatistics(stats) {
    try {
        localStorage.setItem(STATS_STORAGE_KEY, JSON.stringify(stats));
    } catch (e) {
        console.error("Failed to save statistics to localStorage", e);
    }
}

/**
 * Updates statistics based on a new password analysis.
 * @param {object} analysisResult - The result object from analyzePassword.
 */
function trackAnalysis(analysisResult) {
    const stats = loadStatistics();

    stats.totalAnalyzed += 1;
    stats.totalScore += analysisResult.score;

    // Increment strength distribution
    const status = analysisResult.status;
    if (stats.strengthDistribution[status] !== undefined) {
        stats.strengthDistribution[status] += 1;
    }

    // Increment weakness counts for each failed rule
    for (const rule in analysisResult.passedRules) {
        if (!analysisResult.passedRules[rule] && stats.weaknessCounts[rule] !== undefined) {
            stats.weaknessCounts[rule] += 1;
        }
    }

    saveStatistics(stats);
    renderStatistics();
}

/**
 * Renders the statistics interface inside statsSection.
 */
function renderStatistics() {
    const statsContainer = document.getElementById("statsSection");
    if (!statsContainer) return;

    const stats = loadStatistics();
    const averageScore = stats.totalAnalyzed > 0 
        ? Math.round(stats.totalScore / stats.totalAnalyzed) 
        : 0;

    // Calculate percentages for strength distribution
    const getPercentage = (count) => {
        if (stats.totalAnalyzed === 0) return 0;
        return Math.round((count / stats.totalAnalyzed) * 100);
    };

    // Determine average status color
    let avgColorClass = "danger-text";
    if (averageScore > 80) avgColorClass = "success-text";
    else if (averageScore > 60) avgColorClass = "info-text";
    else if (averageScore > 30) avgColorClass = "warning-text";

    statsContainer.innerHTML = `
        <div class="stats-card">
            <h3 class="stats-title">Session Statistics</h3>
            
            <div class="stats-grid">
                <div class="stat-box">
                    <span class="stat-value">${stats.totalAnalyzed}</span>
                    <span class="stat-label">Passwords Scanned</span>
                </div>
                <div class="stat-box">
                    <span class="stat-value ${avgColorClass}">${averageScore}</span>
                    <span class="stat-label">Average Score</span>
                </div>
            </div>

            <div class="distribution-section">
                <h4 class="sub-title">Strength Distribution</h4>
                
                <div class="dist-row">
                    <div class="dist-label-container">
                        <span class="dist-label-tag weak-tag">Weak</span>
                        <span class="dist-count">${stats.strengthDistribution["Weak"]} (${getPercentage(stats.strengthDistribution["Weak"])}%)</span>
                    </div>
                    <div class="dist-bar-bg">
                        <div class="dist-bar-fill weak-bar" style="width: ${getPercentage(stats.strengthDistribution["Weak"])}%"></div>
                    </div>
                </div>

                <div class="dist-row">
                    <div class="dist-label-container">
                        <span class="dist-label-tag medium-tag">Medium</span>
                        <span class="dist-count">${stats.strengthDistribution["Medium"]} (${getPercentage(stats.strengthDistribution["Medium"])}%)</span>
                    </div>
                    <div class="dist-bar-bg">
                        <div class="dist-bar-fill medium-bar" style="width: ${getPercentage(stats.strengthDistribution["Medium"])}%"></div>
                    </div>
                </div>

                <div class="dist-row">
                    <div class="dist-label-container">
                        <span class="dist-label-tag strong-tag">Strong</span>
                        <span class="dist-count">${stats.strengthDistribution["Strong"]} (${getPercentage(stats.strengthDistribution["Strong"])}%)</span>
                    </div>
                    <div class="dist-bar-bg">
                        <div class="dist-bar-fill strong-bar" style="width: ${getPercentage(stats.strengthDistribution["Strong"])}%"></div>
                    </div>
                </div>

                <div class="dist-row">
                    <div class="dist-label-container">
                        <span class="dist-label-tag very-strong-tag">Very Strong</span>
                        <span class="dist-count">${stats.strengthDistribution["Very Strong"]} (${getPercentage(stats.strengthDistribution["Very Strong"])}%)</span>
                    </div>
                    <div class="dist-bar-bg">
                        <div class="dist-bar-fill very-strong-bar" style="width: ${getPercentage(stats.strengthDistribution["Very Strong"])}%"></div>
                    </div>
                </div>
            </div>

            <div class="stats-actions">
                <button id="resetStatsBtn" class="secondary-btn btn-small">Reset Stats</button>
            </div>
        </div>
    `;

    // Bind event listener to reset button
    const resetBtn = document.getElementById("resetStatsBtn");
    if (resetBtn) {
        resetBtn.addEventListener("click", () => {
            resetStatistics();
        });
    }
}

/**
 * Resets the statistics stored in localStorage and redraws.
 */
function resetStatistics() {
    try {
        localStorage.removeItem(STATS_STORAGE_KEY);
    } catch (e) {
        console.error("Failed to remove statistics from localStorage", e);
    }
    renderStatistics();
}
