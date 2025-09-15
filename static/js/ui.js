/**
 * UI management module.
 * Handles user interface interactions and form handling.
 */

import { encryptFile, decryptFile } from './fileops.js';

// ===== UI Initialization =====
export function setupUI() {
    const removeBtn = document.getElementById("remove-file-btn");
    if (removeBtn) {
        removeBtn.style.display = "none";
    }
    initializeEventListeners();
}

async function initializeEventListeners() {
    const elements = {
        algorithm: document.getElementById("algorithm"),
        inputText: document.getElementById("input-text"),
        form: document.getElementById("crypto-form"),
        removeFileBtn: document.getElementById("remove-file-btn"),
        clearAllBtn: document.getElementById("clear-all-btn"),
        generateBtn: document.getElementById("generate-btn"),
        copyPasswordBtn: document.getElementById("copy-btn"),
        copyOutputBtn: document.getElementById("copy-output-btn"),
        toggleSwitch: document.getElementById("operation-toggle"),
        copyShareBtn: document.getElementById("copy-share-btn"),
        shareLink: document.getElementById("share-link"),
        generateKeypairBtn: document.getElementById("generate-keypair-btn"),
        loadPublicKeyBtn: document.getElementById("load-public-key-btn"),
        loadPrivateKeyBtn: document.getElementById("load-private-key-btn"),
        publicKeyFile: document.getElementById("public-key-file"),
        privateKeyFile: document.getElementById("private-key-file")
    };

    if (validateElements(elements)) {
        setupElementListeners(elements);
    }
    await loadAvailableAlgorithms();
    // Initialize algorithm options on page load after algorithms are loaded
    toggleAlgorithmOptions();
}

function validateElements(elements) {
    return elements.algorithm && elements.inputText && elements.form && 
           elements.removeFileBtn && elements.clearAllBtn && elements.generateBtn && 
           elements.copyPasswordBtn && elements.toggleSwitch;
}

function setupElementListeners(elements) {
    elements.algorithm?.addEventListener("change", toggleAlgorithmOptions);
    elements.inputText.addEventListener("input", handleInputChange);
    elements.form.addEventListener("submit", handleSubmit);
    elements.removeFileBtn.addEventListener("click", removeFile);
    elements.clearAllBtn.addEventListener("click", clearAll);
    elements.generateBtn.addEventListener("click", generateRandomPassword);
    elements.copyPasswordBtn.addEventListener("click", () => copyToClipboard("generated-password", "password-copy-feedback"));
    elements.copyOutputBtn?.addEventListener("click", () => copyToClipboard("output-text", "output-copy-feedback"));
    elements.toggleSwitch.addEventListener("change", () => {
        console.log("Mode:", elements.toggleSwitch.checked ? "Decrypt" : "Encrypt");
    });

    // Password generator controls
    setupPasswordGeneratorListeners();

    // Key pair management listeners
    elements.generateKeypairBtn?.addEventListener("click", generateAndDownloadKeyPair);
    elements.loadPublicKeyBtn?.addEventListener("click", () => elements.publicKeyFile?.click());
    elements.loadPrivateKeyBtn?.addEventListener("click", () => elements.privateKeyFile?.click());
    elements.publicKeyFile?.addEventListener("change", handlePublicKeyLoad);
    elements.privateKeyFile?.addEventListener("change", handlePrivateKeyLoad);

    const fileInput = document.getElementById("file-input");
    if (fileInput) {
        fileInput.addEventListener("change", () => {
            const removeBtn = document.getElementById("remove-file-btn");
            if (removeBtn) {
                removeBtn.style.display = fileInput.files.length > 0 ? "inline-block" : "none";
            }
        });
    }

    setupShareLinkListeners(elements);
}

function setupShareLinkListeners(elements) {
    if (elements.copyShareBtn && elements.shareLink) {
        elements.copyShareBtn.addEventListener("click", () => {
            const linkText = elements.shareLink.textContent.trim();
            navigator.clipboard.writeText(linkText).then(() => {
                const feedback = document.getElementById("shared-link-feedback");
                if (feedback) {
                    feedback.style.display = "block";
                    feedback.classList.add("show");
                    setTimeout(() => {
                        feedback.classList.remove("show");
                        setTimeout(() => {
                            feedback.style.display = "none";
                        }, 300);
                    }, 3000);
                }
            });
        });
    }
}


function toggleInputMode() {
    const fileInput = document.getElementById("file-input");
    const textValue = document.getElementById("input-text")?.value.trim();

    const textSection = document.getElementById("text-section");
    const fileSection = document.getElementById("file-section");
    const removeBtn = document.getElementById("remove-file-btn");

    if (!fileInput || !textSection || !fileSection || !removeBtn) return;

    const fileSelected = fileInput.files.length > 0;

    textSection.style.display = fileSelected ? "none" : "flex";
    fileSection.style.display = !textValue ? "flex" : "none";
    removeBtn.style.display = fileSelected ? "inline-block" : "none";
}

async function handleSubmit(event) {
    event.preventDefault();

    const algorithm = document.getElementById("algorithm")?.value;
    const password = document.getElementById("password")?.value;
    const fileInput = document.getElementById("file-input");
    const isDecrypt = document.getElementById("operation-toggle").checked;
    const operation = isDecrypt ? "decrypt" : "encrypt";

    if (!algorithm || !fileInput) return;

    // Check requirements based on algorithm
    let requiresKeypair = false;
    if (window.availableAlgorithms && window.availableAlgorithms[algorithm]) {
        requiresKeypair = window.availableAlgorithms[algorithm].requires_keypair || false;
    } else {
        requiresKeypair = algorithm.includes("hybrid");
    }
    
    if (requiresKeypair) {
        const globalKeys = window.getGlobalKeys ? window.getGlobalKeys() : {};
        if (operation === "encrypt" && !globalKeys.publicKey) {
            return alert("Please load a public key in the Key Pairs Management section for encryption with this algorithm.");
        }
        if (operation === "decrypt" && !globalKeys.privateKey) {
            return alert("Please load a private key in the Key Pairs Management section for decryption with this algorithm.");
        }
    } else if (!password) {
        return alert("Password is required for this algorithm.");
    }

    if (fileInput.files.length > 0) {
        return (operation === "encrypt")
            ? encryptFile(fileInput, password)
            : decryptFile(fileInput, password);
    }

    await handleTextOperation(operation, password);
}

async function handleTextOperation(operation, password) {
    const algorithm = document.getElementById("algorithm")?.value || "aes_gcm";
    
    const payload = {
        message: document.getElementById("input-text")?.value,
        algorithm: algorithm
    };

    // Add appropriate authentication based on algorithm
    let requiresKeypair = false;
    if (window.availableAlgorithms && window.availableAlgorithms[algorithm]) {
        requiresKeypair = window.availableAlgorithms[algorithm].requires_keypair || false;
    } else {
        requiresKeypair = algorithm.includes("hybrid");
    }
    
    if (requiresKeypair) {
        const globalKeys = window.getGlobalKeys ? window.getGlobalKeys() : {};
        if (operation === "encrypt" && globalKeys.publicKey) {
            payload.public_key = globalKeys.publicKey;
        } else if (operation === "decrypt" && globalKeys.privateKey) {
            payload.private_key = globalKeys.privateKey;
        }
    } else {
        payload.password = password;
    }

    try {
        const endpoint = operation === "encrypt" ? "/api/encrypt" : "/api/decrypt";
        const response = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        const outputField = document.getElementById("output-text");
        if (outputField) {
            if (data.error) {
                outputField.value = `[Error] ${data.error}`;
            } else {
                outputField.value = data.result || "[Error] No response received.";
            }
        }
    } catch (err) {
        alert("Error processing request: " + err.message);
    }
}

function removeFile() {
    const fileInput = document.getElementById("file-input");
    if (fileInput) fileInput.value = "";
    const removeBtn = document.getElementById("remove-file-btn");
    if (removeBtn) removeBtn.style.display = 'none';
    toggleInputMode();
}

// ===== Advanced Password Generator =====
function generateRandomPassword() {
    const settings = getPasswordSettings();

    if (!settings.charset || settings.charset.length === 0) {
        alert("Please select at least one character type for password generation!");
        return;
    }

    const password = generatePassword(settings.length, settings.charset);
    const passwordField = document.getElementById("generated-password");

    if (passwordField) {
        passwordField.value = password;
        updatePasswordStrength(password);
        checkForPacman();
    }
}

function getPasswordSettings() {
    const length = parseInt(document.getElementById("password-length-input")?.value || 16);
    const includeUppercase = document.getElementById("include-uppercase")?.checked;
    const includeLowercase = document.getElementById("include-lowercase")?.checked;
    const includeNumbers = document.getElementById("include-numbers")?.checked;
    const includeSpecial = document.getElementById("include-special")?.checked;
    const excludeAmbiguous = document.getElementById("exclude-ambiguous")?.checked;
    const customCharacters = document.getElementById("custom-characters")?.value || "";

    let charset = "";

    // Character sets
    const sets = {
        uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        lowercase: "abcdefghijklmnopqrstuvwxyz",
        numbers: "0123456789",
        special: "!@#$%^&*()_+-=[]{}|;:,.<>?/~"
    };

    // Ambiguous characters to exclude
    const ambiguous = "0O1lI";

    if (includeUppercase) charset += sets.uppercase;
    if (includeLowercase) charset += sets.lowercase;
    if (includeNumbers) charset += sets.numbers;
    if (includeSpecial) charset += sets.special;

    // Add custom characters
    if (customCharacters) {
        charset += customCharacters;
    }

    // Remove ambiguous characters if requested
    if (excludeAmbiguous) {
        charset = charset.split('').filter(char => !ambiguous.includes(char)).join('');
    }

    // Remove duplicates
    charset = [...new Set(charset)].join('');

    return { length, charset, settings: { includeUppercase, includeLowercase, includeNumbers, includeSpecial } };
}

function generatePassword(length, charset) {
    // Use crypto.getRandomValues for cryptographically secure random generation
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);

    return Array.from(array, (x) => charset[x % charset.length]).join('');
}

function updatePasswordStrength(password) {
    const score = calculatePasswordStrength(password);
    const strengthText = document.getElementById("password-strength-text");
    const strengthFill = document.getElementById("password-strength-fill");
    const strengthScore = document.getElementById("strength-score");
    const strengthFeedback = document.getElementById("strength-feedback");

    if (!strengthText || !strengthFill || !strengthScore || !strengthFeedback) return;

    strengthScore.textContent = `Score: ${score.score}/100`;
    strengthFeedback.textContent = score.feedback;

    // Update strength level and colors
    let level, color, width;
    if (score.score < 30) {
        level = "Very Weak";
        color = "#ff4444";
        width = "20%";
    } else if (score.score < 50) {
        level = "Weak";
        color = "#ff8800";
        width = "40%";
    } else if (score.score < 70) {
        level = "Fair";
        color = "#ffaa00";
        width = "60%";
    } else if (score.score < 85) {
        level = "Strong";
        color = "#88ff00";
        width = "80%";
    } else {
        level = "Very Strong";
        color = "#00ff44";
        width = "100%";
    }

    strengthText.textContent = level;
    strengthText.style.color = color;
    strengthFill.style.backgroundColor = color;
    strengthFill.style.width = width;
}

function calculatePasswordStrength(password) {
    if (!password) return { score: 0, feedback: "Enter a password to see strength analysis" };

    let score = 0;
    const feedback = [];

    // Length scoring
    if (password.length >= 8) score += 10;
    if (password.length >= 12) score += 10;
    if (password.length >= 16) score += 10;
    if (password.length >= 20) score += 5;

    // Character variety scoring
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[^a-zA-Z0-9]/.test(password);

    let varieties = 0;
    if (hasLower) { score += 5; varieties++; }
    if (hasUpper) { score += 5; varieties++; }
    if (hasNumber) { score += 5; varieties++; }
    if (hasSpecial) { score += 10; varieties++; }

    // Bonus for character variety
    if (varieties >= 3) score += 10;
    if (varieties === 4) score += 5;

    // Pattern penalties
    if (/(.)\1{2,}/.test(password)) {
        score -= 10;
        feedback.push("Avoid repeating characters");
    }

    if (/123|abc|qwe|password|admin|test/i.test(password)) {
        score -= 15;
        feedback.push("Avoid common patterns or words");
    }

    // Entropy calculation
    const uniqueChars = new Set(password).size;
    const entropy = password.length * Math.log2(uniqueChars);
    if (entropy > 60) score += 15;
    else if (entropy > 40) score += 10;
    else if (entropy > 30) score += 5;

    // Generate specific feedback
    if (password.length < 8) feedback.push("Use at least 8 characters");
    if (password.length < 12) feedback.push("12+ characters recommended");
    if (!hasLower) feedback.push("Add lowercase letters");
    if (!hasUpper) feedback.push("Add uppercase letters");
    if (!hasNumber) feedback.push("Add numbers");
    if (!hasSpecial) feedback.push("Add special characters");

    if (feedback.length === 0) {
        feedback.push("Excellent password strength!");
    }

    return {
        score: Math.min(100, Math.max(0, score)),
        feedback: feedback.join(", ")
    };
}

function setupPasswordGeneratorListeners() {
    // Modal controls
    const settingsBtn = document.getElementById("password-settings-btn");
    const modal = document.getElementById("password-settings-modal");
    const closeBtn = document.getElementById("close-password-settings");
    const applyBtn = document.getElementById("apply-password-settings");
    const resetBtn = document.getElementById("reset-password-settings");

    if (settingsBtn && modal) {
        settingsBtn.addEventListener("click", () => {
            modal.style.display = "flex";
            updateCharsetPreview();
        });
    }

    if (closeBtn && modal) {
        closeBtn.addEventListener("click", () => {
            modal.style.display = "none";
        });
    }

    // Close modal when clicking outside
    if (modal) {
        modal.addEventListener("click", (e) => {
            if (e.target === modal) {
                modal.style.display = "none";
            }
        });
    }

    if (applyBtn && modal) {
        applyBtn.addEventListener("click", () => {
            generateRandomPassword();
            modal.style.display = "none";
            showPasswordFeedback("Settings applied and password regenerated!");
        });
    }

    if (resetBtn) {
        resetBtn.addEventListener("click", () => {
            resetPasswordSettings();
            updateCharsetPreview();
            showPasswordFeedback("Settings reset to defaults!");
        });
    }

    // Length controls (slider and number input)
    const lengthSlider = document.getElementById("password-length");
    const lengthInput = document.getElementById("password-length-input");

    if (lengthSlider && lengthInput) {
        // Sync slider to number input
        lengthSlider.addEventListener("input", () => {
            lengthInput.value = lengthSlider.value;
            updateCharsetPreview();
        });

        // Sync number input to slider
        lengthInput.addEventListener("input", () => {
            let value = parseInt(lengthInput.value);

            // Validate bounds
            if (value < 8) {
                value = 8;
                lengthInput.value = 8;
            } else if (value > 128) {
                value = 128;
                lengthInput.value = 128;
            }

            lengthSlider.value = value;
            updateCharsetPreview();
        });

        // Handle edge cases for number input
        lengthInput.addEventListener("blur", () => {
            if (!lengthInput.value || lengthInput.value < 8) {
                lengthInput.value = 8;
                lengthSlider.value = 8;
                updateCharsetPreview();
            }
        });

        // Allow Enter key to apply changes
        lengthInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") {
                lengthInput.blur();
            }
        });
    }

    // Character set checkboxes
    const checkboxes = [
        "include-uppercase",
        "include-lowercase",
        "include-numbers",
        "include-special",
        "exclude-ambiguous"
    ];

    checkboxes.forEach(id => {
        const checkbox = document.getElementById(id);
        if (checkbox) {
            checkbox.addEventListener("change", () => {
                updateCharsetPreview();
            });
        }
    });

    // Custom characters input
    const customCharsInput = document.getElementById("custom-characters");
    if (customCharsInput) {
        customCharsInput.addEventListener("input", () => {
            updateCharsetPreview();
        });
    }

    // Password visibility toggle
    const toggleVisibilityBtn = document.getElementById("toggle-password-visibility");
    const passwordField = document.getElementById("generated-password");

    if (toggleVisibilityBtn && passwordField) {
        toggleVisibilityBtn.addEventListener("click", () => {
            if (passwordField.type === "password") {
                passwordField.type = "text";
                toggleVisibilityBtn.textContent = "🙈";
            } else {
                passwordField.type = "password";
                toggleVisibilityBtn.textContent = "👁️";
            }
        });
    }

    // Use password in form button
    const usePasswordBtn = document.getElementById("use-password-btn");
    if (usePasswordBtn) {
        usePasswordBtn.addEventListener("click", () => {
            const generatedPassword = document.getElementById("generated-password")?.value;
            const passwordInput = document.getElementById("password");

            if (generatedPassword && passwordInput) {
                passwordInput.value = generatedPassword;
                showPasswordFeedback("Password applied to form!");
            }
        });
    }

    // Monitor password field for manual changes to update strength
    if (passwordField) {
        passwordField.addEventListener("input", () => {
            updatePasswordStrength(passwordField.value);
        });
    }

    // Generate initial password
    generateRandomPassword();
}

function updateCharsetPreview() {
    const settings = getPasswordSettings();
    const preview = document.getElementById("charset-preview");

    if (preview) {
        if (settings.charset && settings.charset.length > 0) {
            preview.textContent = `Characters (${settings.charset.length}): ${settings.charset}`;
        } else {
            preview.textContent = "⚠️ No character types selected! Please select at least one character type.";
            preview.style.color = "#ff6b6b";
        }
    }
}

function resetPasswordSettings() {
    // Reset to default values
    document.getElementById("password-length").value = 16;
    document.getElementById("password-length-input").value = 16;
    document.getElementById("include-uppercase").checked = true;
    document.getElementById("include-lowercase").checked = true;
    document.getElementById("include-numbers").checked = true;
    document.getElementById("include-special").checked = true;
    document.getElementById("exclude-ambiguous").checked = false;
    document.getElementById("custom-characters").value = "";
}

function showPasswordFeedback(message) {
    const feedback = document.getElementById("password-copy-feedback");
    if (feedback) {
        const originalText = feedback.textContent;
        feedback.textContent = message;
        showFeedback(feedback);
        // Reset feedback text after showing
        setTimeout(() => {
            feedback.textContent = originalText;
        }, 3000);
    }
}

function copyToClipboard(elementId, feedbackId) {
    const el = document.getElementById(elementId);
    const feedback = document.getElementById(feedbackId);

    if (!el || !el.value) return;

    const textarea = document.createElement('textarea');
    textarea.value = el.value;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);

    textarea.select();
    textarea.setSelectionRange(0, 99999);

    try {
        navigator.clipboard.writeText(el.value).then(() => {
            showFeedback(feedback);
        }).catch(() => {
            document.execCommand('copy');
            showFeedback(feedback);
        });
    } catch (err) {
        document.execCommand('copy');
        showFeedback(feedback);
    }

    document.body.removeChild(textarea);
}

function showFeedback(feedback) {
    if (feedback) {
        feedback.style.display = "block";
        feedback.classList.add("show");
        setTimeout(() => {
            feedback.classList.remove("show");
            setTimeout(() => {
                feedback.style.display = "none";
            }, 300);
        }, 3000);
    }
}

function clearAll() {
    const fields = ["input-text", "output-text", "file-input", "password"];
    fields.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = "";
    });
    removeFile();
    toggleInputMode();
    document.getElementById("pacman-section")?.style.setProperty("display", "none");
    document.getElementById("encoding-section")?.style.setProperty("display", "block");
}

function handleInputChange() {
    toggleInputMode();
    checkForPacman();
}

function checkForPacman() {
    const val = document.getElementById("input-text").value.trim().toLowerCase();
    const pacSection = document.getElementById("pacman-section");
    const encSection = document.getElementById("encoding-section");

    if (val.includes("pacman") && pacSection.style.display !== "block") {
        pacSection.style.display = "block";
        encSection.style.display = "none";
        window.startPacman();
    } else if (pacSection.style.display === "block" && !val.includes("pacman")) {
        window.exitGame();
    }
}

function copyShareLink() {
    const linkEl = document.getElementById("share-link");
    const feedback = document.getElementById("shared-link-feedback");

    if (!linkEl) return;

    const linkText = linkEl.href || linkEl.textContent.trim();

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(linkText).then(() => {
            showCopyFeedback(feedback);
        }).catch(() => {
            fallbackCopy(linkText, feedback);
        });
    } else {
        fallbackCopy(linkText, feedback);
    }
}

function fallbackCopy(text, feedbackEl) {
    const tempInput = document.createElement("input");
    tempInput.value = text;
    document.body.appendChild(tempInput);
    tempInput.select();

    try {
        document.execCommand("copy");
        showCopyFeedback(feedbackEl);
    } catch (err) {
        alert("Copy failed. Please copy manually.");
    }

    document.body.removeChild(tempInput);
}

function showCopyFeedback(feedbackEl) {
    if (!feedbackEl) return;
    feedbackEl.style.display = "block";
    feedbackEl.classList.add("show");

    setTimeout(() => {
        feedbackEl.classList.remove("show");
        setTimeout(() => {
            feedbackEl.style.display = "none";
        }, 300);
    }, 3000);
}

// ===== Algorithm Management =====
async function loadAvailableAlgorithms() {
    try {
        const response = await fetch('/api/algorithms');
        const data = await response.json();
        
        if (response.ok && data.algorithms) {
            // Store algorithms globally for use in other functions
            window.availableAlgorithms = data.algorithms;
            updateAlgorithmDropdown(data.algorithms);
        }
    } catch (error) {
        console.error('Failed to load algorithms:', error);
    }
}

function updateAlgorithmDropdown(algorithms) {
    const algorithmSelect = document.getElementById('algorithm');
    const shareAlgorithmSelect = document.getElementById('share-algorithm');
    
    // Update main encryption/decryption algorithm dropdown
    if (algorithmSelect) {
        algorithmSelect.innerHTML = '';
        
        let firstOption = null;
        for (const [key, algo] of Object.entries(algorithms)) {
            if (algo.supports_text) {
                const option = document.createElement('option');
                option.value = key;
                option.textContent = `${algo.name}${algo.requires_keypair ? ' (requires keypair)' : ''}`;
                algorithmSelect.appendChild(option);
                
                // Remember the first option (should be a non-keypair algorithm)
                if (!firstOption) {
                    firstOption = key;
                }
            }
        }
        
        // Ensure the first option is selected
        if (firstOption) {
            algorithmSelect.value = firstOption;
        }
    }
    
    // Update PacShare algorithm dropdown (for file uploads)
    if (shareAlgorithmSelect) {
        shareAlgorithmSelect.innerHTML = '';
        
        let firstFileOption = null;
        for (const [key, algo] of Object.entries(algorithms)) {
            if (algo.supports_file) {
                const option = document.createElement('option');
                option.value = key;
                option.textContent = `${algo.name}${algo.requires_keypair ? ' (requires keypair)' : ''}`;
                shareAlgorithmSelect.appendChild(option);
                
                // Remember the first file-supporting option
                if (!firstFileOption) {
                    firstFileOption = key;
                }
            }
        }
        
        // Set the first file-supporting option as selected
        if (firstFileOption) {
            shareAlgorithmSelect.value = firstFileOption;
        }
    }
    
    // Update Key Pairs Management dropdown
    const keypairAlgorithmSelect = document.getElementById('keypair-algorithm');
    if (keypairAlgorithmSelect) {
        // Clear existing options except the hardcoded ones
        const options = keypairAlgorithmSelect.querySelectorAll('option');
        options.forEach(option => {
            if (option.value !== 'rsa_hybrid' && option.value !== 'pqcrypto') {
                option.remove();
            }
        });
        
        // Show/hide post-quantum option based on availability
        const pqOption = document.getElementById('pqcrypto-option');
        if (pqOption) {
            pqOption.style.display = algorithms.pqcrypto ? 'block' : 'none';
        }
        
        // If rsa_hybrid is not available, hide it
        const rsaOption = keypairAlgorithmSelect.querySelector('option[value="rsa_hybrid"]');
        if (rsaOption) {
            rsaOption.style.display = algorithms.rsa_hybrid ? 'block' : 'none';
        }
    }
    
    // Call toggleAlgorithmOptions after dropdown is populated
    toggleAlgorithmOptions();
}

function toggleAlgorithmOptions() {
    const algorithm = document.getElementById("algorithm")?.value;
    const keypairSection = document.getElementById("keypair-section");
    const passwordInput = document.getElementById("password-input");
    
    if (!algorithm) return;
    
    // Check if algorithm requires keypair by looking at available algorithms data
    let requiresKeypair = false;
    if (window.availableAlgorithms && window.availableAlgorithms[algorithm]) {
        requiresKeypair = window.availableAlgorithms[algorithm].requires_keypair || false;
    } else {
        // Fallback to checking name for "hybrid"
        requiresKeypair = algorithm.includes("hybrid");
    }
    
    // Show/hide keypair section only for algorithms that require it
    if (keypairSection) {
        keypairSection.style.display = requiresKeypair ? "block" : "none";
    }
    
    // Show/hide password input (opposite of keypair section)
    if (passwordInput) {
        passwordInput.style.display = requiresKeypair ? "none" : "block";
    }
    
    // Update key status based on global keys
    const globalKeys = window.getGlobalKeys ? window.getGlobalKeys() : {};
    const publicStatus = document.getElementById("public-key-status");
    const privateStatus = document.getElementById("private-key-status");
    
    if (!requiresKeypair) {
        if (publicStatus) publicStatus.style.display = "none";
        if (privateStatus) privateStatus.style.display = "none";
    } else {
        // Show key status if keys are loaded in global store
        if (publicStatus) publicStatus.style.display = globalKeys.publicKey ? "block" : "none";
        if (privateStatus) privateStatus.style.display = globalKeys.privateKey ? "block" : "none";
    }
}

// ===== File-based Key Management =====
async function generateAndDownloadKeyPair() {
    const algorithm = document.getElementById("algorithm")?.value;
    
    let requiresKeypair = false;
    if (window.availableAlgorithms && window.availableAlgorithms[algorithm]) {
        requiresKeypair = window.availableAlgorithms[algorithm].requires_keypair || false;
    } else {
        requiresKeypair = algorithm.includes("hybrid");
    }
    
    if (!algorithm || !requiresKeypair) {
        alert("Key pair generation is only available for algorithms that require key pairs");
        return;
    }
    
    try {
        const response = await fetch('/api/generate-keypair', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ algorithm: algorithm })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Download public key
            downloadTextAsFile(data.public_key, `${algorithm}_public_key.pub`, 'text/plain');
            
            // Download private key  
            downloadTextAsFile(data.private_key, `${algorithm}_private_key.key`, 'text/plain');
            
            alert("✅ Key pair generated and downloaded!\n\n📁 Files saved:\n• Public Key: " + `${algorithm}_public_key.pub` + "\n• Private Key: " + `${algorithm}_private_key.key` + "\n\n🔐 Use public key for encryption, private key for decryption.");
        } else {
            alert(`Error generating key pair: ${data.error}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

function downloadTextAsFile(text, filename, mimeType) {
    const blob = new Blob([text], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function handlePublicKeyLoad(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = function(e) {
        // Update global keys instead of window variables
        if (window.setGlobalKeys) {
            window.setGlobalKeys({ publicKey: e.target.result });
        }
        document.getElementById("public-key-status").style.display = "block";
        console.log("Public key loaded successfully and synced to global store");
    };
    reader.readAsText(file);
}

function handlePrivateKeyLoad(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = function(e) {
        // Update global keys instead of window variables
        if (window.setGlobalKeys) {
            window.setGlobalKeys({ privateKey: e.target.result });
        }
        document.getElementById("private-key-status").style.display = "block";
        console.log("Private key loaded successfully and synced to global store");
    };
    reader.readAsText(file);
}

function startPacman() { }
function exitGame() { }