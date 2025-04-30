// ui.js
import { encryptFile, decryptFile } from './fileops.js';

/**
 * Initialize all UI functionality after DOM is loaded
 */
export function setupUI() {
    toggleEncryptionOptions();
    toggleInputMode();

    const encryptionTypeEl = document.getElementById("encryption-type");
    const inputTextEl = document.getElementById("input-text");
    const formEl = document.getElementById("crypto-form");
    const removeFileBtn = document.getElementById("remove-file-btn");
    const clearAllBtn = document.getElementById("clear-all-btn");
    const generateBtn = document.getElementById("generate-btn");
    const copyPasswordBtn = document.getElementById("copy-btn");
    const copyOutputBtn = document.getElementById("copy-output-btn");
    const toggleSwitch = document.getElementById("operation-toggle");
    const copyShareBtn = document.getElementById("copy-share-btn");
    const shareLink = document.getElementById("share-link");

    if (
        encryptionTypeEl && inputTextEl && formEl && removeFileBtn &&
        clearAllBtn && generateBtn && copyPasswordBtn && toggleSwitch
    ) {
        encryptionTypeEl.addEventListener("change", toggleEncryptionOptions);
        inputTextEl.addEventListener("input", () => {
            toggleInputMode();
            checkForPacman();
        });
        formEl.addEventListener("submit", handleSubmit);
        removeFileBtn.addEventListener("click", removeFile);
        clearAllBtn.addEventListener("click", clearAll);
        generateBtn.addEventListener("click", generateRandomPassword);
        copyPasswordBtn.addEventListener("click", () => copyToClipboard("generated-password", "password-copy-feedback"));
        copyOutputBtn?.addEventListener("click", () => copyToClipboard("output-text", "output-copy-feedback"));
        toggleSwitch.addEventListener("change", updateToggleLabels);

        const copySharedLinkBtn = document.getElementById("copy-shared-link");
        const sharedLinkEl = document.getElementById("shared-link");

        if (copySharedLinkBtn && sharedLinkEl) {
            copySharedLinkBtn.addEventListener("click", () => {
                navigator.clipboard.writeText(sharedLinkEl.textContent.trim()).then(() => {
                    const feedback = document.getElementById("shared-link-feedback");
                    if (feedback) {
                        feedback.classList.remove("hidden");
                        feedback.classList.add("show");

                        setTimeout(() => {
                            feedback.classList.remove("show");
                            feedback.classList.add("hidden");
                        }, 3000);
                    }
                });
            });

            sharedLinkEl.scrollIntoView({ behavior: "smooth" });
        }
    }
}




function toggleEncryptionOptions() {
    const type = document.getElementById("encryption-type").value.trim().toLowerCase();
    const passwordInputWrapper = document.getElementById("password-input");
    const isAdvanced = type.includes("advanced");

    if (passwordInputWrapper) {
        if (isAdvanced) {
            passwordInputWrapper.classList.remove("hidden");
        } else {
            passwordInputWrapper.classList.add("hidden");
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
    if (passwordField) passwordField.value = password;
}

function copyToClipboard(elementId, feedbackId) {
    const el = document.getElementById(elementId);
    const feedback = document.getElementById(feedbackId);
    if (!el || !feedback) return;

    navigator.clipboard.writeText(el.textContent || el.value || "").then(() => {
        feedback.classList.add("show");
        setTimeout(() => {
            feedback.classList.remove("show");
        }, 3000);
    });
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
