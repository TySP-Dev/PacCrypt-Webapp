/**
 * Enhanced PacShare Module
 * Handles bulk uploads and single file uploads seamlessly
 */

class PacShareEnhanced {
    constructor() {
        this.selectedFiles = [];
        this.uploadResults = [];
        this.settings = {
            enable2FA: false,
            autoClearPasswords: true,
            autoCopyLinks: true,
            showUploadProgress: true,
            scrollToResults: true,
            maxUploadSizeMB: 25,
            validateFileTypes: false,
            concurrentUploads: 1,
            enableFilePreview: true,
            rememberAlgorithm: true
        };
        this.setupEventListeners();
        this.loadSettings();
    }

    setupEventListeners() {
        // Drag & Drop Zone
        const dropZone = document.getElementById('pacshare-drop-zone');
        const fileInput = document.getElementById('upload-file');
        const fileSelect = document.getElementById('pacshare-file-select');

        console.log('PacShare setup - dropZone:', dropZone, 'fileInput:', fileInput, 'fileSelect:', fileSelect);

        if (dropZone && fileInput) {
            console.log('Setting up PacShare drag & drop events');
            // Drag & Drop Events
            dropZone.addEventListener('dragover', this.handleDragOver.bind(this));
            dropZone.addEventListener('dragleave', this.handleDragLeave.bind(this));
            dropZone.addEventListener('drop', this.handleDrop.bind(this));
            dropZone.addEventListener('click', () => {
                console.log('PacShare drop zone clicked, opening file input');
                fileInput.click();
            });

            // File Input Events
            fileInput.addEventListener('change', this.handleFileSelect.bind(this));
        } else {
            console.error('PacShare elements not found - dropZone:', dropZone, 'fileInput:', fileInput);
        }

        if (fileSelect) {
            console.log('Setting up PacShare file select button');
            fileSelect.addEventListener('click', (e) => {
                console.log('PacShare file select button clicked');
                e.stopPropagation();
                fileInput.click();
            });
        } else {
            console.error('PacShare file select button not found');
        }

        // Clear files button
        const clearBtn = document.getElementById('pacshare-clear-files');
        if (clearBtn) {
            clearBtn.addEventListener('click', this.clearFiles.bind(this));
        }

        // Enhanced form submission
        const uploadForm = document.getElementById('upload-form');
        if (uploadForm) {
            // Remove existing event listener first
            uploadForm.replaceWith(uploadForm.cloneNode(true));
            const newForm = document.getElementById('upload-form');
            newForm.addEventListener('submit', this.handleEnhancedSubmit.bind(this));
        }

        // Settings modal controls
        this.setupSettingsModal();
    }

    handleDragOver(e) {
        e.preventDefault();
        e.stopPropagation();
        document.getElementById('pacshare-drop-zone').classList.add('drag-over');
    }

    handleDragLeave(e) {
        e.preventDefault();
        e.stopPropagation();
        document.getElementById('pacshare-drop-zone').classList.remove('drag-over');
    }

    handleDrop(e) {
        e.preventDefault();
        e.stopPropagation();
        document.getElementById('pacshare-drop-zone').classList.remove('drag-over');

        const files = Array.from(e.dataTransfer.files);
        this.addFiles(files);
    }

    handleFileSelect(e) {
        const files = Array.from(e.target.files);
        this.addFiles(files);
    }

    addFiles(newFiles) {
        // Filter out duplicates
        newFiles = newFiles.filter(newFile =>
            !this.selectedFiles.some(existingFile =>
                existingFile.name === newFile.name && existingFile.size === newFile.size
            )
        );

        this.selectedFiles.push(...newFiles);
        this.updateFileDisplay();
        this.updateUI();
    }

    updateFileDisplay() {
        const fileListContainer = document.getElementById('pacshare-file-list');
        const filesContainer = document.getElementById('pacshare-files-container');
        const uploadBtn = document.getElementById('pacshare-upload-btn');

        if (!filesContainer || !fileListContainer) return;

        if (this.selectedFiles.length === 0) {
            fileListContainer.style.display = 'none';
            if (uploadBtn) uploadBtn.textContent = 'Upload and Generate Link';
            return;
        }

        fileListContainer.style.display = 'block';
        filesContainer.innerHTML = '';

        // Update button text based on file count
        if (uploadBtn) {
            uploadBtn.textContent = this.selectedFiles.length === 1
                ? 'Upload and Generate Link'
                : `Upload ${this.selectedFiles.length} Files and Generate Links`;
        }

        this.selectedFiles.forEach((file, index) => {
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item';
            fileItem.innerHTML = `
                <div class="file-info">
                    <div class="file-name">${file.name}</div>
                    <div class="file-size">${this.formatFileSize(file.size)}</div>
                </div>
                <div class="file-actions">
                    <button type="button" onclick="pacShareEnhanced.previewFile(${index})" style="padding: 5px 10px; font-size: 0.8em;">Preview</button>
                    <button type="button" onclick="pacShareEnhanced.removeFile(${index})" class="danger-button" style="padding: 5px 10px; font-size: 0.8em;">Remove</button>
                </div>
            `;
            filesContainer.appendChild(fileItem);
        });
    }

    async previewFile(index) {
        const file = this.selectedFiles[index];
        if (!file) return;

        const previewContainer = document.createElement('div');
        previewContainer.className = 'file-preview-container';

        const header = document.createElement('div');
        header.className = 'file-preview-header';
        header.textContent = `Preview: ${file.name}`;

        const content = document.createElement('div');
        content.className = 'file-preview-content';

        // Handle different file types
        if (file.type.startsWith('text/') || this.isTextFile(file.name)) {
            try {
                const text = await this.readFileAsText(file);
                content.textContent = text.length > 2000 ? text.substring(0, 2000) + '...' : text;
            } catch (error) {
                content.textContent = 'Error reading file: ' + error.message;
            }
        } else if (file.type.startsWith('image/')) {
            const img = document.createElement('img');
            img.className = 'image-preview';
            img.src = URL.createObjectURL(file);
            img.onload = () => URL.revokeObjectURL(img.src);
            content.appendChild(img);
        } else {
            content.innerHTML = `
                <div style="color: #888;">
                    File Type: ${file.type || 'Unknown'}<br>
                    Size: ${this.formatFileSize(file.size)}<br>
                    Preview not available for this file type.
                </div>
            `;
        }

        previewContainer.appendChild(header);
        previewContainer.appendChild(content);

        // Remove existing preview
        const existingPreview = document.querySelector('.file-preview-container');
        if (existingPreview) {
            existingPreview.remove();
        }

        // Add new preview after the file list
        const fileList = document.getElementById('pacshare-files-container');
        if (fileList) {
            fileList.parentNode.insertBefore(previewContainer, fileList.nextSibling);
        }
    }

    removeFile(index) {
        this.selectedFiles.splice(index, 1);
        this.updateFileDisplay();

        // Remove preview if it exists
        const existingPreview = document.querySelector('.file-preview-container');
        if (existingPreview) {
            existingPreview.remove();
        }
    }

    clearFiles() {
        this.selectedFiles = [];
        this.updateFileDisplay();

        // Clear file input
        const fileInput = document.getElementById('upload-file');
        if (fileInput) fileInput.value = '';

        // Remove preview if it exists
        const existingPreview = document.querySelector('.file-preview-container');
        if (existingPreview) {
            existingPreview.remove();
        }

        this.hideResults();
    }

    async handleEnhancedSubmit(e) {
        e.preventDefault();

        if (this.selectedFiles.length === 0) {
            alert('Please select at least one file to upload.');
            return;
        }

        const algorithm = document.getElementById('share-algorithm')?.value;
        const encPassword = document.querySelector('input[name="enc_password"]')?.value;
        const pickupPassword = document.querySelector('input[name="pickup_password"]')?.value;
        const enable2FA = this.settings.enable2FA;

        if (!algorithm || !encPassword || !pickupPassword) {
            alert('Please fill in all required fields.');
            return;
        }

        if (this.selectedFiles.length === 1) {
            // Single file - use existing logic
            await this.uploadSingleFile(this.selectedFiles[0], algorithm, encPassword, pickupPassword, enable2FA);
        } else {
            // Multiple files - use bulk upload
            await this.uploadMultipleFiles(algorithm, encPassword, pickupPassword, enable2FA);
        }
    }

    async uploadSingleFile(file, algorithm, encPassword, pickupPassword, enable2FA) {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('algorithm', algorithm);
        formData.append('enc_password', encPassword);
        formData.append('pickup_password', pickupPassword);
        if (enable2FA) formData.append('enable_2fa', 'on');

        try {
            const response = await fetch('/', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (data.error) {
                alert(data.error);
                return;
            }

            if (data.success && data.pickup_url) {
                this.showSingleResult(data);
            }

        } catch (error) {
            alert('Error uploading file: ' + error.message);
        }
    }

    async uploadMultipleFiles(algorithm, encPassword, pickupPassword, enable2FA) {
        this.uploadResults = [];
        this.showProgress();

        // Upload files sequentially to avoid overwhelming the server
        for (let i = 0; i < this.selectedFiles.length; i++) {
            const file = this.selectedFiles[i];
            this.updateFileProgress(i, 'uploading');

            try {
                const formData = new FormData();
                formData.append('file', file);
                formData.append('algorithm', algorithm);
                formData.append('enc_password', encPassword);
                formData.append('pickup_password', pickupPassword);
                if (enable2FA) formData.append('enable_2fa', 'on');

                const response = await fetch('/', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.error) {
                    this.uploadResults.push({ file, error: data.error, success: false });
                    this.updateFileProgress(i, 'error');
                } else if (data.success && data.pickup_url) {
                    this.uploadResults.push({ file, data, success: true });
                    this.updateFileProgress(i, 'completed');
                }

            } catch (error) {
                this.uploadResults.push({ file, error: error.message, success: false });
                this.updateFileProgress(i, 'error');
            }

            this.updateOverallProgress(i + 1, this.selectedFiles.length);
        }

        this.showResults();
    }

    showProgress() {
        const progressSection = document.getElementById('pacshare-progress');
        if (progressSection) {
            progressSection.style.display = 'block';
        }

        this.updateOverallProgress(0, this.selectedFiles.length);
        this.initializeFileProgress();
    }

    initializeFileProgress() {
        const progressContainer = document.getElementById('pacshare-file-progress');
        if (!progressContainer) return;

        progressContainer.innerHTML = '';

        this.selectedFiles.forEach((file, index) => {
            const progressItem = document.createElement('div');
            progressItem.className = 'file-progress-item';
            progressItem.innerHTML = `
                <div class="file-progress-name">${file.name}</div>
                <div class="file-progress-status" id="pacshare-progress-${index}">Waiting</div>
            `;
            progressContainer.appendChild(progressItem);
        });
    }

    updateFileProgress(index, status) {
        const statusElement = document.getElementById(`pacshare-progress-${index}`);
        if (!statusElement) return;

        statusElement.className = `file-progress-status status-${status}`;

        switch (status) {
            case 'uploading':
                statusElement.textContent = 'Uploading...';
                break;
            case 'completed':
                statusElement.textContent = 'Completed';
                break;
            case 'error':
                statusElement.textContent = 'Error';
                break;
            default:
                statusElement.textContent = 'Waiting';
        }
    }

    updateOverallProgress(completed, total) {
        const progressBar = document.getElementById('pacshare-overall-bar');
        const progressText = document.getElementById('pacshare-overall-text');

        if (progressBar) {
            const percentage = total > 0 ? (completed / total) * 100 : 0;
            progressBar.style.width = `${percentage}%`;
        }

        if (progressText) {
            progressText.textContent = `${completed} / ${total} files uploaded`;
        }
    }

    showSingleResult(data) {
        // Use existing single result display logic
        const shareLink = document.getElementById('share-link');
        const shareLinkContainer = document.getElementById('share-link-container');

        if (shareLink && shareLinkContainer) {
            shareLink.href = data.pickup_url;
            shareLink.textContent = data.pickup_url;
            shareLinkContainer.style.display = 'flex';

            // Handle 2FA if enabled
            if (data.qr_code_url) {
                this.showTwoFactorSetup(data.qr_code_url, data.service_name, data.totp_secret);
            }

            // Clear form
            this.clearForm();

            // Scroll to results
            shareLinkContainer.scrollIntoView({ behavior: 'smooth' });
        }
    }

    showResults() {
        const resultsSection = document.getElementById('pacshare-results');
        const resultsList = document.getElementById('pacshare-results-list');

        if (!resultsSection || !resultsList) return;

        resultsSection.style.display = 'block';
        resultsList.innerHTML = '';

        const successCount = this.uploadResults.filter(r => r.success).length;
        const totalCount = this.uploadResults.length;

        // Add summary
        const summary = document.createElement('div');
        summary.style.cssText = 'padding: 15px; border-bottom: 1px solid #333; background-color: #1a1a1a; font-weight: bold;';
        summary.innerHTML = `
            <div style="color: #00ff99;">Upload Complete</div>
            <div style="font-size: 0.9em; color: #ccc; margin-top: 5px;">
                ${successCount} successful, ${totalCount - successCount} failed out of ${totalCount} files
            </div>
        `;
        resultsList.appendChild(summary);

        // Add individual results
        this.uploadResults.forEach((result, index) => {
            const resultItem = document.createElement('div');
            resultItem.className = 'result-item';

            if (result.success) {
                resultItem.innerHTML = `
                    <div class="result-info">
                        <div class="result-name">✅ ${result.file.name}</div>
                        <div class="result-details">
                            <a href="${result.data.pickup_url}" target="_blank" style="color: #00ff99;">${result.data.pickup_url}</a>
                        </div>
                    </div>
                    <div class="result-actions">
                        <button type="button" onclick="pacShareEnhanced.copyLink('${result.data.pickup_url}')" style="padding: 5px 10px; font-size: 0.8em;">Copy Link</button>
                    </div>
                `;
            } else {
                resultItem.innerHTML = `
                    <div class="result-info">
                        <div class="result-name">❌ ${result.file.name}</div>
                        <div class="result-details">${result.error}</div>
                    </div>
                `;
            }

            resultsList.appendChild(resultItem);
        });

        // Clear form and scroll to results
        this.clearForm();
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    copyLink(url) {
        navigator.clipboard.writeText(url).then(() => {
            this.showToast('Link copied to clipboard!');
        }).catch(() => {
            // Fallback
            const textArea = document.createElement('textarea');
            textArea.value = url;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            this.showToast('Link copied to clipboard!');
        });
    }

    showToast(message) {
        const toast = document.createElement('div');
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background-color: #00ff99;
            color: #000;
            padding: 10px 20px;
            border-radius: 5px;
            font-weight: bold;
            z-index: 10000;
            opacity: 1;
            transition: opacity 0.3s ease;
        `;
        toast.textContent = message;

        document.body.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, 2000);
    }

    clearForm() {
        // Clear passwords but keep algorithm
        const encPassword = document.querySelector('input[name="enc_password"]');
        const pickupPassword = document.querySelector('input[name="pickup_password"]');
        const enable2FA = document.getElementById('enable-2fa');

        if (encPassword) encPassword.value = '';
        if (pickupPassword) pickupPassword.value = '';
        if (enable2FA) enable2FA.checked = false;

        // Clear selected files
        this.clearFiles();
    }

    hideResults() {
        const sections = ['pacshare-results', 'pacshare-progress', 'share-link-container'];
        sections.forEach(id => {
            const section = document.getElementById(id);
            if (section) section.style.display = 'none';
        });
    }

    updateUI() {
        // Hide results when new files are selected
        this.hideResults();
    }

    // Utility methods
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    isTextFile(filename) {
        const textExtensions = ['.txt', '.md', '.js', '.html', '.css', '.json', '.xml', '.csv', '.log', '.py', '.java', '.c', '.cpp', '.h'];
        return textExtensions.some(ext => filename.toLowerCase().endsWith(ext));
    }

    readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = e => resolve(e.target.result);
            reader.onerror = e => reject(new Error('Failed to read file'));
            reader.readAsText(file);
        });
    }

    showTwoFactorSetup(qrCodeUrl, serviceName, totpSecret) {
        const container = document.getElementById('tfa-setup-container');
        const qrImage = document.getElementById('tfa-qr-image');
        const tfaString = document.getElementById('tfa-string');

        if (container && qrImage && tfaString) {
            qrImage.src = qrCodeUrl;
            tfaString.value = totpSecret;
            container.style.display = 'block';
            container.scrollIntoView({ behavior: 'smooth' });
        }
    }

    // Settings Modal Methods
    setupSettingsModal() {
        const settingsBtn = document.getElementById("pacshare-settings-btn");
        const modal = document.getElementById("pacshare-settings-modal");
        const closeBtn = document.getElementById("close-pacshare-settings");
        const applyBtn = document.getElementById("apply-pacshare-settings");
        const resetBtn = document.getElementById("reset-pacshare-settings");

        if (settingsBtn && modal) {
            settingsBtn.addEventListener("click", () => {
                modal.style.display = "flex";
                this.updateSettingsModal();
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
                this.resetSettings();
            });
        }

        // Input validation
        const uploadSizeInput = document.getElementById("max-upload-size-input");
        const concurrentInput = document.getElementById("concurrent-uploads-input");

        if (uploadSizeInput) {
            uploadSizeInput.addEventListener("input", () => {
                let value = parseInt(uploadSizeInput.value);
                if (value < 1) uploadSizeInput.value = 1;
                else if (value > 1000) uploadSizeInput.value = 1000;
                this.updateSettingsSummary();
            });
        }

        if (concurrentInput) {
            concurrentInput.addEventListener("input", () => {
                let value = parseInt(concurrentInput.value);
                if (value < 1) concurrentInput.value = 1;
                else if (value > 10) concurrentInput.value = 10;
                this.updateSettingsSummary();
            });
        }

        // Update summary when checkboxes change
        const checkboxIds = [
            "enable-2fa-setting", "auto-clear-passwords", "auto-copy-links",
            "show-upload-progress", "scroll-to-results", "validate-file-types",
            "enable-file-preview", "remember-algorithm"
        ];

        checkboxIds.forEach(id => {
            const checkbox = document.getElementById(id);
            if (checkbox) {
                checkbox.addEventListener("change", () => {
                    this.updateSettingsSummary();
                });
            }
        });
    }

    updateSettingsModal() {
        // Set checkbox values
        const checkboxMap = {
            "enable-2fa-setting": "enable2FA",
            "auto-clear-passwords": "autoClearPasswords",
            "auto-copy-links": "autoCopyLinks",
            "show-upload-progress": "showUploadProgress",
            "scroll-to-results": "scrollToResults",
            "validate-file-types": "validateFileTypes",
            "enable-file-preview": "enableFilePreview",
            "remember-algorithm": "rememberAlgorithm"
        };

        Object.entries(checkboxMap).forEach(([id, setting]) => {
            const checkbox = document.getElementById(id);
            if (checkbox) {
                checkbox.checked = this.settings[setting];
            }
        });

        // Set number inputs
        const uploadSizeInput = document.getElementById("max-upload-size-input");
        const concurrentInput = document.getElementById("concurrent-uploads-input");

        if (uploadSizeInput) uploadSizeInput.value = this.settings.maxUploadSizeMB;
        if (concurrentInput) concurrentInput.value = this.settings.concurrentUploads;

        this.updateSettingsSummary();
    }

    updateSettingsSummary() {
        const summary = document.getElementById("pacshare-settings-summary");
        if (!summary) return;

        const enable2FA = document.getElementById("enable-2fa-setting")?.checked || this.settings.enable2FA;
        const autoClearPasswords = document.getElementById("auto-clear-passwords")?.checked || this.settings.autoClearPasswords;
        const maxSize = document.getElementById("max-upload-size-input")?.value || this.settings.maxUploadSizeMB;
        const concurrent = document.getElementById("concurrent-uploads-input")?.value || this.settings.concurrentUploads;

        summary.innerHTML = `
            • 2FA: ${enable2FA ? 'Enabled' : 'Disabled'}<br>
            • Auto-clear passwords: ${autoClearPasswords ? 'Yes' : 'No'}<br>
            • Max file size: ${maxSize} MB<br>
            • Upload mode: ${concurrent == 1 ? 'Sequential' : `${concurrent} concurrent`}<br>
            • File preview: ${this.settings.enableFilePreview ? 'Enabled' : 'Disabled'}
        `;
    }

    applySettings() {
        // Get checkbox values
        const checkboxMap = {
            "enable-2fa-setting": "enable2FA",
            "auto-clear-passwords": "autoClearPasswords",
            "auto-copy-links": "autoCopyLinks",
            "show-upload-progress": "showUploadProgress",
            "scroll-to-results": "scrollToResults",
            "validate-file-types": "validateFileTypes",
            "enable-file-preview": "enableFilePreview",
            "remember-algorithm": "rememberAlgorithm"
        };

        Object.entries(checkboxMap).forEach(([id, setting]) => {
            const checkbox = document.getElementById(id);
            if (checkbox) {
                this.settings[setting] = checkbox.checked;
            }
        });

        // Get number inputs
        const uploadSizeInput = document.getElementById("max-upload-size-input");
        const concurrentInput = document.getElementById("concurrent-uploads-input");

        if (uploadSizeInput) this.settings.maxUploadSizeMB = parseInt(uploadSizeInput.value) || 25;
        if (concurrentInput) this.settings.concurrentUploads = parseInt(concurrentInput.value) || 1;

        this.saveSettings();
        this.showToast("PacShare settings applied successfully!");
    }

    resetSettings() {
        this.settings = {
            enable2FA: false,
            autoClearPasswords: true,
            autoCopyLinks: true,
            showUploadProgress: true,
            scrollToResults: true,
            maxUploadSizeMB: 25,
            validateFileTypes: false,
            concurrentUploads: 1,
            enableFilePreview: true,
            rememberAlgorithm: true
        };

        this.updateSettingsModal();
        this.showToast("Settings reset to defaults!");
    }

    loadSettings() {
        try {
            const saved = localStorage.getItem('paccrypt-pacshare-settings');
            if (saved) {
                this.settings = { ...this.settings, ...JSON.parse(saved) };
            }
        } catch (error) {
            console.warn('Failed to load PacShare settings:', error);
        }
    }

    saveSettings() {
        try {
            localStorage.setItem('paccrypt-pacshare-settings', JSON.stringify(this.settings));
        } catch (error) {
            console.warn('Failed to save PacShare settings:', error);
        }
    }
}

// Initialize enhanced PacShare when DOM is loaded
let pacShareEnhanced;
document.addEventListener('DOMContentLoaded', () => {
    pacShareEnhanced = new PacShareEnhanced();
    // Make available globally for onclick handlers
    window.pacShareEnhanced = pacShareEnhanced;
});