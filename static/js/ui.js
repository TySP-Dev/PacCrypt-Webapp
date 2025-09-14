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

function generateRandomPassword() {
    const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+[]{}|;:,.<>?/~";
    const length = 30;
    const password = Array.from({ length }, () =>
        charset.charAt(Math.floor(Math.random() * charset.length))
    ).join("");
    const passwordField = document.getElementById("generated-password");
    if (passwordField) {
        passwordField.value = password;
        checkForPacman();
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