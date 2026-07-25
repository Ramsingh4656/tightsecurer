/**
 * Application controller for the Password Security Assistant.
 * Coordinates user interaction, triggers password analysis and generation, 
 * manages visibility toggles, and handles notification alerts.
 * Follows camelCase naming convention.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Cache DOM Elements
    const passwordInput = document.getElementById("passwordInput");
    const togglePasswordBtn = document.getElementById("togglePasswordBtn");
    const eyeIconOpen = document.getElementById("eyeIconOpen");
    const eyeIconClosed = document.getElementById("eyeIconClosed");
    const analyzeBtn = document.getElementById("analyzeBtn");
    
    const resultsSection = document.getElementById("resultsSection");
    const scoreDisplay = document.getElementById("scoreDisplay");
    const statusLabel = document.getElementById("statusLabel");
    const strengthMeter = document.getElementById("strengthMeter");
    
    const successMessage = document.getElementById("successMessage");
    const weaknessBox = document.getElementById("weaknessBox");
    const weaknessesList = document.getElementById("weaknessesList");
    const suggestionBox = document.getElementById("suggestionBox");
    const suggestionsList = document.getElementById("suggestionsList");
    const generateBtn = document.getElementById("generateBtn");
    
    const generatorSection = document.getElementById("generatorSection");
    const generatedPasswordBox = document.getElementById("generatedPasswordBox");
    const copyBtn = document.getElementById("copyBtn");
    const regenerateBtn = document.getElementById("regenerateBtn");
    const lengthSlider = document.getElementById("lengthSlider");
    const lengthDisplay = document.getElementById("lengthDisplay");

    // Initialize UI
    if (typeof renderStatistics === "function") {
        renderStatistics();
    }

    // Toggle Password Visibility
    if (togglePasswordBtn && passwordInput) {
        togglePasswordBtn.addEventListener("click", () => {
            const isPasswordType = passwordInput.type === "password";
            passwordInput.type = isPasswordType ? "text" : "password";
            
            if (isPasswordType) {
                eyeIconOpen.classList.add("hidden");
                eyeIconClosed.classList.remove("hidden");
            } else {
                eyeIconOpen.classList.remove("hidden");
                eyeIconClosed.classList.add("hidden");
            }
        });
    }

    // Perform Password Analysis on click
    if (analyzeBtn) {
        analyzeBtn.addEventListener("click", runAnalysis);
    }

    // Allow running analysis by pressing Enter key in the input field
    if (passwordInput) {
        passwordInput.addEventListener("keypress", (event) => {
            if (event.key === "Enter") {
                runAnalysis();
            }
        });
    }

    // Slider controls update length value dynamically
    if (lengthSlider && lengthDisplay) {
        lengthSlider.addEventListener("input", (event) => {
            lengthDisplay.textContent = event.target.value;
        });
    }

    // Show generator card and generate first strong password
    if (generateBtn) {
        generateBtn.addEventListener("click", () => {
            if (generatorSection) {
                generatorSection.classList.remove("hidden-element");
                
                // Set default length from slider and generate
                const length = parseInt(lengthSlider ? lengthSlider.value : 16, 10);
                triggerPasswordGeneration(length);

                // Scroll generator card smoothly into view
                generatorSection.scrollIntoView({ behavior: "smooth", block: "nearest" });
            }
        });
    }

    // Regenerate password on click
    if (regenerateBtn) {
        regenerateBtn.addEventListener("click", () => {
            // Spin animation on button
            regenerateBtn.classList.add("animate-shake");
            setTimeout(() => {
                regenerateBtn.classList.remove("animate-shake");
            }, 600);

            const length = parseInt(lengthSlider ? lengthSlider.value : 16, 10);
            triggerPasswordGeneration(length);
        });
    }

    // Copy generated password to clipboard
    if (copyBtn) {
        copyBtn.addEventListener("click", async () => {
            const textToCopy = generatedPasswordBox ? generatedPasswordBox.textContent : "";
            if (!textToCopy || textToCopy === "Press regenerate...") {
                showToast("No password available to copy.", "error");
                return;
            }

            if (typeof copyToClipboard === "function") {
                const success = await copyToClipboard(textToCopy);
                if (success) {
                    showToast("Password copied to clipboard!", "success");
                } else {
                    showToast("Failed to copy password automatically.", "error");
                }
            }
        });
    }

    /**
     * Executes the password scan, updates result cards, shows recommendations
     * and records metrics.
     */
    function runAnalysis() {
        const passwordValue = passwordInput ? passwordInput.value : "";

        // Check if empty input and show shake feedback
        if (!passwordValue) {
            const cardEl = passwordInput.closest(".card");
            if (cardEl) {
                cardEl.classList.add("animate-shake");
                setTimeout(() => {
                    cardEl.classList.remove("animate-shake");
                }, 600);
            }
            showToast("Please enter a password to analyze.", "error");
            
            // Hide the results & generator if active
            if (resultsSection) resultsSection.classList.add("hidden-element");
            if (generatorSection) generatorSection.classList.add("hidden-element");
            return;
        }

        if (typeof analyzePassword !== "function") {
            console.error("analyzePassword is not defined in analyzer.js");
            return;
        }

        // Run security calculations
        const result = analyzePassword(passwordValue);

        // Display results block
        if (resultsSection) {
            resultsSection.classList.remove("hidden-element");
        }

        // Render Score and Status texts
        if (scoreDisplay) scoreDisplay.textContent = result.score;
        if (statusLabel) statusLabel.textContent = result.status;

        // Reset classes
        const statusClasses = ["weak-color", "medium-color", "strong-color", "very-strong-color"];
        const bgClasses = ["bg-weak", "bg-medium", "bg-strong", "bg-very-strong"];
        
        statusClasses.forEach(cls => {
            scoreDisplay.classList.remove(cls);
            statusLabel.classList.remove(cls);
        });
        bgClasses.forEach(cls => {
            strengthMeter.classList.remove(cls);
        });

        // Set matching theme class based on strength score levels
        let themeClass = "";
        let bgClass = "";
        
        if (result.status === "Very Strong") {
            themeClass = "very-strong-color";
            bgClass = "bg-very-strong";
        } else if (result.status === "Strong") {
            themeClass = "strong-color";
            bgClass = "bg-strong";
        } else if (result.status === "Medium") {
            themeClass = "medium-color";
            bgClass = "bg-medium";
        } else {
            themeClass = "weak-color";
            bgClass = "bg-weak";
        }

        scoreDisplay.classList.add(themeClass);
        statusLabel.classList.add(themeClass);
        strengthMeter.classList.add(bgClass);

        // Adjust meter percentage bar
        strengthMeter.style.width = `${result.score}%`;

        // Update checklist rule indicators (metric pills)
        for (const rule in result.passedRules) {
            const pill = document.querySelector(`.metric-pill[data-rule="${rule}"]`);
            if (pill) {
                if (result.passedRules[rule]) {
                    pill.classList.add("pill-pass");
                    pill.classList.remove("pill-fail");
                } else {
                    pill.classList.add("pill-fail");
                    pill.classList.remove("pill-pass");
                }
            }
        }

        // Show/Hide recommendations depending on password strength
        // Strict workflow: Strong/Very Strong gets success message only, Weak/Medium gets improvement steps
        if (result.status === "Strong" || result.status === "Very Strong") {
            if (successMessage) successMessage.classList.remove("hidden-element");
            if (weaknessBox) weaknessBox.classList.add("hidden-element");
            if (suggestionBox) suggestionBox.classList.add("hidden-element");
            if (generateBtn) generateBtn.classList.add("hidden-element");
            
            // Hide generator block since they have a strong password already
            if (generatorSection) generatorSection.classList.add("hidden-element");
        } else {
            if (successMessage) successMessage.classList.add("hidden-element");
            if (weaknessBox) weaknessBox.classList.remove("hidden-element");
            if (suggestionBox) suggestionBox.classList.remove("hidden-element");
            if (generateBtn) generateBtn.classList.remove("hidden-element");

            // Fill weaknesses list
            if (weaknessesList) {
                weaknessesList.innerHTML = "";
                result.weaknesses.forEach(w => {
                    const li = document.createElement("li");
                    li.textContent = w;
                    weaknessesList.appendChild(li);
                });
            }

            // Fill suggestions list
            if (suggestionsList) {
                suggestionsList.innerHTML = "";
                result.suggestions.forEach(s => {
                    const li = document.createElement("li");
                    li.textContent = s;
                    suggestionsList.appendChild(li);
                });
            }
        }

        // Log to session history/localstorage statistics
        if (typeof updateStatistics === "function") {
            updateStatistics(passwordValue, result);
        } else if (typeof trackAnalysis === "function") {
            trackAnalysis(result);
        }
    }

    /**
     * Triggers generation of secure password string and renders it.
     * @param {number} length - Password length.
     */
    function triggerPasswordGeneration(length) {
        if (typeof generateStrongPassword === "function" && generatedPasswordBox) {
            const password = generateStrongPassword(length);
            generatedPasswordBox.textContent = password;
            
            // Add custom dynamic glow/animation trigger
            generatedPasswordBox.classList.add("animate-fade-in");
            setTimeout(() => {
                generatedPasswordBox.classList.remove("animate-fade-in");
            }, 800);
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
});
