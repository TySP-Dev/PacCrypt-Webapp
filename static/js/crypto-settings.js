/**
 * Crypto Settings Module
 * Handles the encryption settings modal and mode switching
 */

class CryptoSettings {
    constructor() {
        this.currentMode = 'single';
        this.settings = {
            processingMode: 'single',
            enableFilePreview: true,
            autoDownloadResults: true,
            sequentialProcessing: true,
            showDetailedProgress: true,
            stopOnError: false,
            maxFileSizeMB: 100
        };
        this.setupEventListeners();
        this.loadSettings();
    }

    setupEventListeners() {
        // Modal controls
        const settingsBtn = document.getElementById("crypto-settings-btn");
        const modal = document.getElementById("crypto-settings-modal");
        const closeBtn = document.getElementById("close-crypto-settings");
        const applyBtn = document.getElementById("apply-crypto-settings");
        const resetBtn = document.getElementById("reset-crypto-settings");

        if (settingsBtn && modal) {
            settingsBtn.addEventListener("click", () => {
                modal.style.display = "flex";
                this.updateModalFromSettings();
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
                this.applySettings();
                modal.style.display = "none";
            });
        }

        if (resetBtn) {
            resetBtn.addEventListener("click", () => {
                this.resetToDefaults();
            });
        }

        // Processing mode radio buttons
        const singleModeRadio = document.getElementById("single-file-mode-radio");
        const bulkModeRadio = document.getElementById("bulk-file-mode-radio");

        if (singleModeRadio) {
            singleModeRadio.addEventListener("change", () => {
                if (singleModeRadio.checked) {
                    this.toggleBulkOptions(false);
                }
            });
        }

        if (bulkModeRadio) {
            bulkModeRadio.addEventListener("change", () => {
                if (bulkModeRadio.checked) {
                    this.toggleBulkOptions(true);
                }
            });
        }

        // File size input validation
        const fileSizeInput = document.getElementById("max-file-size-input");
        if (fileSizeInput) {
            fileSizeInput.addEventListener("input", () => {
                let value = parseInt(fileSizeInput.value);
                if (value < 1) {
                    fileSizeInput.value = 1;
                } else if (value > 1000) {
                    fileSizeInput.value = 1000;
                }
            });
        }
    }

    toggleBulkOptions(show) {
        const bulkOptions = document.getElementById("bulk-options");
        if (bulkOptions) {
            bulkOptions.style.display = show ? "block" : "none";
        }
    }

    updateModalFromSettings() {
        // Set radio buttons
        const singleModeRadio = document.getElementById("single-file-mode-radio");
        const bulkModeRadio = document.getElementById("bulk-file-mode-radio");

        if (this.settings.processingMode === 'single') {
            if (singleModeRadio) singleModeRadio.checked = true;
            this.toggleBulkOptions(false);
        } else {
            if (bulkModeRadio) bulkModeRadio.checked = true;
            this.toggleBulkOptions(true);
        }

        // Set checkboxes
        const checkboxes = [
            { id: "enable-file-preview", setting: "enableFilePreview" },
            { id: "auto-download-results", setting: "autoDownloadResults" },
            { id: "sequential-processing", setting: "sequentialProcessing" },
            { id: "show-detailed-progress", setting: "showDetailedProgress" },
            { id: "stop-on-error", setting: "stopOnError" }
        ];

        checkboxes.forEach(checkbox => {
            const element = document.getElementById(checkbox.id);
            if (element) {
                element.checked = this.settings[checkbox.setting];
            }
        });

        // Set file size
        const fileSizeInput = document.getElementById("max-file-size-input");
        if (fileSizeInput) {
            fileSizeInput.value = this.settings.maxFileSizeMB;
        }
    }

    applySettings() {
        // Get processing mode
        const singleModeRadio = document.getElementById("single-file-mode-radio");
        const bulkModeRadio = document.getElementById("bulk-file-mode-radio");

        if (singleModeRadio && singleModeRadio.checked) {
            this.settings.processingMode = 'single';
        } else if (bulkModeRadio && bulkModeRadio.checked) {
            this.settings.processingMode = 'bulk';
        }

        // Get checkbox values
        const checkboxes = [
            { id: "enable-file-preview", setting: "enableFilePreview" },
            { id: "auto-download-results", setting: "autoDownloadResults" },
            { id: "sequential-processing", setting: "sequentialProcessing" },
            { id: "show-detailed-progress", setting: "showDetailedProgress" },
            { id: "stop-on-error", setting: "stopOnError" }
        ];

        checkboxes.forEach(checkbox => {
            const element = document.getElementById(checkbox.id);
            if (element) {
                this.settings[checkbox.setting] = element.checked;
            }
        });

        // Get file size
        const fileSizeInput = document.getElementById("max-file-size-input");
        if (fileSizeInput) {
            this.settings.maxFileSizeMB = parseInt(fileSizeInput.value) || 100;
        }

        // Apply the mode change
        this.switchMode(this.settings.processingMode);

        // Save settings
        this.saveSettings();

        // Show feedback
        this.showFeedback("Settings applied successfully!");
    }

    switchMode(mode) {
        this.currentMode = mode;

        const singleFileMode = document.getElementById("single-file-mode");
        const bulkFileMode = document.getElementById("bulk-file-mode");

        if (mode === 'single') {
            if (singleFileMode) singleFileMode.style.display = "block";
            if (bulkFileMode) bulkFileMode.style.display = "none";
        } else {
            if (singleFileMode) singleFileMode.style.display = "none";
            if (bulkFileMode) bulkFileMode.style.display = "block";
        }

        // Update the form submit handler
        this.updateFormHandler();
    }

    updateFormHandler() {
        const cryptoForm = document.getElementById("crypto-form");
        if (!cryptoForm) return;

        // Remove existing event listeners by cloning the form
        const newForm = cryptoForm.cloneNode(true);
        cryptoForm.parentNode.replaceChild(newForm, cryptoForm);

        // Add the appropriate event listener
        if (this.currentMode === 'single') {
            newForm.addEventListener("submit", this.handleSingleFileSubmit.bind(this));
        } else {
            newForm.addEventListener("submit", this.handleBulkFileSubmit.bind(this));
        }
    }

    async handleSingleFileSubmit(event) {
        event.preventDefault();

        const algorithm = document.getElementById("algorithm")?.value;
        const password = document.getElementById("password")?.value;
        const fileInput = document.getElementById("file-input");
        const isDecrypt = document.getElementById("operation-toggle").checked;

        if (!algorithm || !fileInput) return;

        // Use existing single file handling logic
        if (window.handleSubmit) {
            window.handleSubmit(event);
        }
    }

    async handleBulkFileSubmit(event) {
        event.preventDefault();

        // Use bulk operations functionality
        if (window.bulkOps && window.bulkOps.processFiles) {
            await window.bulkOps.processFiles();
        }
    }

    resetToDefaults() {
        this.settings = {
            processingMode: 'single',
            enableFilePreview: true,
            autoDownloadResults: true,
            sequentialProcessing: true,
            showDetailedProgress: true,
            stopOnError: false,
            maxFileSizeMB: 100
        };

        this.updateModalFromSettings();
        this.showFeedback("Settings reset to defaults!");
    }

    loadSettings() {
        try {
            const saved = localStorage.getItem('paccrypt-crypto-settings');
            if (saved) {
                this.settings = { ...this.settings, ...JSON.parse(saved) };
            }
        } catch (error) {
            console.warn('Failed to load crypto settings:', error);
        }

        // Apply the loaded settings
        this.switchMode(this.settings.processingMode);
    }

    saveSettings() {
        try {
            localStorage.setItem('paccrypt-crypto-settings', JSON.stringify(this.settings));
        } catch (error) {
            console.warn('Failed to save crypto settings:', error);
        }
    }

    showFeedback(message) {
        // Use the existing feedback system or create a temporary one
        const feedbackDiv = document.createElement('div');
        feedbackDiv.className = 'copy-feedback';
        feedbackDiv.textContent = message;
        feedbackDiv.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background-color: #00ff99;
            color: #000;
            padding: 10px 20px;
            border-radius: 5px;
            font-weight: bold;
            z-index: 10000;
            display: block;
        `;

        document.body.appendChild(feedbackDiv);

        setTimeout(() => {
            feedbackDiv.style.opacity = '0';
            feedbackDiv.style.transition = 'opacity 0.3s ease';
            setTimeout(() => {
                if (feedbackDiv.parentNode) {
                    feedbackDiv.parentNode.removeChild(feedbackDiv);
                }
            }, 300);
        }, 2000);
    }

    // Public methods for external access
    getCurrentMode() {
        return this.currentMode;
    }

    getSettings() {
        return { ...this.settings };
    }

    isBulkMode() {
        return this.currentMode === 'bulk';
    }
}

// Initialize crypto settings when DOM is loaded
let cryptoSettings;
document.addEventListener('DOMContentLoaded', () => {
    cryptoSettings = new CryptoSettings();
});

// Make cryptoSettings available globally
window.cryptoSettings = cryptoSettings;