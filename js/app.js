/**
 * Application controller for the Password Security Assistant.
 * Coordinates user interaction, triggers password analysis and generation, 
 * manages visibility toggles, and handles notification alerts.
 * Follows camelCase naming convention.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Cache DOM Elements using utility selector
    const passwordInput = typeof $ === "function" ? $("#passwordInput") : document.getElementById("passwordInput");
    const togglePasswordBtn = typeof $ === "function" ? $("#togglePasswordBtn") : document.getElementById("togglePasswordBtn");
    const eyeIconOpen = typeof $ === "function" ? $("#eyeIconOpen") : document.getElementById("eyeIconOpen");
    const eyeIconClosed = typeof $ === "function" ? $("#eyeIconClosed") : document.getElementById("eyeIconClosed");
    const analyzeBtn = typeof $ === "function" ? $("#analyzeBtn") : document.getElementById("analyzeBtn");
    
    const resultsSection = typeof $ === "function" ? $("#resultsSection") : document.getElementById("resultsSection");
    const scoreDisplay = typeof $ === "function" ? $("#scoreDisplay") : document.getElementById("scoreDisplay");
    const statusLabel = typeof $ === "function" ? $("#statusLabel") : document.getElementById("statusLabel");
    const strengthMeter = typeof $ === "function" ? $("#strengthMeter") : document.getElementById("strengthMeter");
    
    const successMessage = typeof $ === "function" ? $("#successMessage") : document.getElementById("successMessage");
    const weaknessBox = typeof $ === "function" ? $("#weaknessBox") : document.getElementById("weaknessBox");
    const weaknessesList = typeof $ === "function" ? $("#weaknessesList") : document.getElementById("weaknessesList");
    const suggestionBox = typeof $ === "function" ? $("#suggestionBox") : document.getElementById("suggestionBox");
    const suggestionsList = typeof $ === "function" ? $("#suggestionsList") : document.getElementById("suggestionsList");
    const generateBtn = typeof $ === "function" ? $("#generateBtn") : document.getElementById("generateBtn");
    
    const generatorSection = typeof $ === "function" ? $("#generatorSection") : document.getElementById("generatorSection");
    const generatedPasswordBox = typeof $ === "function" ? $("#generatedPasswordBox") : document.getElementById("generatedPasswordBox");
    const copyBtn = typeof $ === "function" ? $("#copyBtn") : document.getElementById("copyBtn");
    const regenerateBtn = typeof $ === "function" ? $("#regenerateBtn") : document.getElementById("regenerateBtn");
    const lengthSlider = typeof $ === "function" ? $("#lengthSlider") : document.getElementById("lengthSlider");
    const lengthDisplay = typeof $ === "function" ? $("#lengthDisplay") : document.getElementById("lengthDisplay");

    // Initialize UI
    if (typeof renderStatistics === "function") {
        renderStatistics();
    }

    // Enforce slider min length to be 12 to guarantee strong generated passwords
    if (lengthSlider) {
        lengthSlider.min = "12";
        if (parseInt(lengthSlider.value, 10) < 12) {
            lengthSlider.value = "12";
        }
    }
    if (lengthDisplay && lengthSlider) {
        lengthDisplay.textContent = lengthSlider.value;
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
        if (typeof generatePassword === "function" && generatedPasswordBox) {
            // Retrieve options and set length
            const options = typeof getGeneratorOptions === "function" ? getGeneratorOptions() : {};
            options.length = length;
            const password = generatePassword(options);
            generatedPasswordBox.textContent = password;
            
            // Add custom dynamic glow/animation trigger
            generatedPasswordBox.classList.add("animate-fade-in");
            setTimeout(() => {
                generatedPasswordBox.classList.remove("animate-fade-in");
            }, 800);
        }
    }
});
