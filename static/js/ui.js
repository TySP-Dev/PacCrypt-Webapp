/**
 * UI management module.
 * Handles user interface interactions and form handling.
 */

import { encryptFile, decryptFile } from './fileops.js';

// ===== UI Initialization =====
export function setupUI() {
    // Set initial state of remove button to hidden
    const removeBtn = document.getElementById("remove-file-btn");
    if (removeBtn) {
        removeBtn.style.display = "none";
    }
    
    initializeEventListeners();
}

// ===== Event Listeners =====
function initializeEventListeners() {
    const elements = {
        encryptionType: document.getElementById("encryption-type"),
        inputText: document.getElementById("input-text"),
        form: document.getElementById("crypto-form"),
        removeFileBtn: document.getElementById("remove-file-btn"),
        clearAllBtn: document.getElementById("clear-all-btn"),
        generateBtn: document.getElementById("generate-btn"),
        copyPasswordBtn: document.getElementById("copy-btn"),
        copyOutputBtn: document.getElementById("copy-output-btn"),
        toggleSwitch: document.getElementById("operation-toggle"),
        copyShareBtn: document.getElementById("copy-share-btn"),
        shareLink: document.getElementById("share-link")
    };

    if (validateElements(elements)) {
        setupElementListeners(elements);
    }
}

function validateElements(elements) {
    return elements.encryptionType && elements.inputText && elements.form && 
           elements.removeFileBtn && elements.clearAllBtn && elements.generateBtn && 
           elements.copyPasswordBtn && elements.toggleSwitch;
}

function setupElementListeners(elements) {
    elements.encryptionType.addEventListener("change", toggleEncryptionOptions);
    elements.inputText.addEventListener("input", handleInputChange);
    elements.form.addEventListener("submit", handleSubmit);
    elements.removeFileBtn.addEventListener("click", removeFile);
    elements.clearAllBtn.addEventListener("click", clearAll);
    elements.generateBtn.addEventListener("click", generateRandomPassword);
    elements.copyPasswordBtn.addEventListener("click", () => copyToClipboard("generated-password", "password-copy-feedback"));
    elements.copyOutputBtn?.addEventListener("click", () => copyToClipboard("output-text", "output-copy-feedback"));
    elements.toggleSwitch.addEventListener("change", updateToggleLabels);

    // Add file input change listener
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

// ===== UI State Management =====
function toggleEncryptionOptions() {
    const type = document.getElementById("encryption-type").value.trim().toLowerCase();
    const passwordInputWrapper = document.getElementById("password-input");
    const fileSection = document.querySelector("#encoding-section #file-section");
    const isAdvanced = type.includes("advanced");

    if (passwordInputWrapper) {
        if (isAdvanced) {
            passwordInputWrapper.classList.remove("hidden");
        } else {
            passwordInputWrapper.classList.add("hidden");
        }
    }

    if (fileSection) {
        if (isAdvanced) {
            fileSection.classList.remove("hidden");
        } else {
            fileSection.classList.add("hidden");
        }
    }

    updateToggleLabels();
    toggleInputMode();
}

function updateToggleLabels() {
    const type = document.getElementById("encryption-type")?.value;
    const leftLabel = document.getElementById("toggle-left-label");
    const rightLabel = document.getElementById("toggle-right-label");

    if (!type || !leftLabel || !rightLabel) return;

    const isAdvanced = type.toLowerCase().includes("advanced");
    leftLabel.textContent = isAdvanced ? "Encrypt" : "Encode";
    rightLabel.textContent = isAdvanced ? "Decrypt" : "Decode";
}

function toggleInputMode() {
    const fileInput = document.getElementById("file-input");
    const textValue = document.getElementById("input-text")?.value.trim();
    const isAdvanced = document.getElementById("encryption-type")?.value === "advanced";

    const textSection = document.getElementById("text-section");
    const fileSection = document.getElementById("file-section");
    const removeBtn = document.getElementById("remove-file-btn");

    if (!fileInput || !textSection || !fileSection || !removeBtn) return;

    const fileSelected = fileInput.files.length > 0;

    textSection.style.display = fileSelected ? "none" : "flex";
    fileSection.style.display = (isAdvanced && !textValue) ? "flex" : "none";
    removeBtn.style.display = fileSelected ? "inline-block" : "none";
}

// ===== Form Handling =====
async function handleSubmit(event) {
    event.preventDefault();

    const encryptionType = document.getElementById("encryption-type")?.value;
    const password = document.getElementById("password")?.value;
    const fileInput = document.getElementById("file-input");
    const isDecrypt = document.getElementById("operation-toggle").checked;
    const operation = isDecrypt ? "decrypt" : "encrypt";

    if (!encryptionType || !fileInput) return;

    if (encryptionType === "advanced" && !password) {
        return alert("Password is required for advanced encryption.");
    }

    if (fileInput.files.length > 0) {
        return (operation === "encrypt")
            ? encryptFile(fileInput, password)
            : decryptFile(fileInput, password);
    }

    await handleTextOperation(encryptionType, operation, password);
}

async function handleTextOperation(encryptionType, operation, password) {
    const payload = {
        "encryption-type": encryptionType,
        operation: operation,
        message: document.getElementById("input-text")?.value,
        password: password
    };

    try {
        const response = await fetch("/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await response.json();
        document.getElementById("output-text").value = data.result;
    } catch (err) {
        alert("Error processing request: " + err.message);
    }
}

// ===== Utility Functions =====
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
        // Check if we should start Pacman
        checkForPacman();
    }
}

function copyToClipboard(elementId, feedbackId) {
    const el = document.getElementById(elementId);
    const feedback = document.getElementById(feedbackId);

    if (!el || !el.value) return;

    // Create a temporary textarea element
    const textarea = document.createElement('textarea');
    textarea.value = el.value;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    
    // Select and copy the text
    textarea.select();
    textarea.setSelectionRange(0, 99999); // For mobile devices
    
    try {
        // Try using the modern clipboard API first
        navigator.clipboard.writeText(el.value).then(() => {
            showFeedback(feedback);
        }).catch(() => {
            // Fallback to execCommand for older browsers
            document.execCommand('copy');
            showFeedback(feedback);
        });
    } catch (err) {
        // Final fallback
        document.execCommand('copy');
        showFeedback(feedback);
    }
    
    // Clean up
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

function startPacman() { }
function exitGame() { }


