/**
 * Bulk Operations Module
 * Handles bulk file encryption/decryption, drag & drop, and file preview
 */

class BulkOperations {
    constructor() {
        this.files = [];
        this.results = [];
        this.isProcessing = false;
        this.setupEventListeners();
        this.populateAlgorithmDropdown();
    }

    setupEventListeners() {
        // Drag & Drop Zone
        const dropZone = document.getElementById('bulk-drop-zone');
        const fileInput = document.getElementById('bulk-file-input');
        const fileSelect = document.getElementById('bulk-file-select');

        console.log('Bulk setup - dropZone:', dropZone, 'fileInput:', fileInput, 'fileSelect:', fileSelect);

        if (dropZone && fileInput) {
            console.log('Setting up bulk drag & drop events');
            // Drag & Drop Events
            dropZone.addEventListener('dragover', this.handleDragOver.bind(this));
            dropZone.addEventListener('dragleave', this.handleDragLeave.bind(this));
            dropZone.addEventListener('drop', this.handleDrop.bind(this));
            dropZone.addEventListener('click', () => {
                console.log('Bulk drop zone clicked, opening file input');
                fileInput.click();
            });

            // File Input Events
            fileInput.addEventListener('change', this.handleFileSelect.bind(this));
        } else {
            console.error('Bulk elements not found - dropZone:', dropZone, 'fileInput:', fileInput);
        }

        if (fileSelect) {
            console.log('Setting up bulk file select button');
            fileSelect.addEventListener('click', (e) => {
                console.log('Bulk file select button clicked');
                e.stopPropagation();
                fileInput.click();
            });
        } else {
            console.error('Bulk file select button not found');
        }

        // Control Buttons
        const processBtn = document.getElementById('bulk-process-btn');
        const clearBtn = document.getElementById('bulk-clear-btn');
        const downloadAllBtn = document.getElementById('bulk-download-all');
        const resetBtn = document.getElementById('bulk-reset');

        if (processBtn) processBtn.addEventListener('click', this.processFiles.bind(this));
        if (clearBtn) clearBtn.addEventListener('click', this.clearFiles.bind(this));
        if (downloadAllBtn) downloadAllBtn.addEventListener('click', this.downloadAllResults.bind(this));
        if (resetBtn) resetBtn.addEventListener('click', this.reset.bind(this));
    }

    handleDragOver(e) {
        e.preventDefault();
        e.stopPropagation();
        document.getElementById('bulk-drop-zone').classList.add('drag-over');
    }

    handleDragLeave(e) {
        e.preventDefault();
        e.stopPropagation();
        document.getElementById('bulk-drop-zone').classList.remove('drag-over');
    }

    handleDrop(e) {
        e.preventDefault();
        e.stopPropagation();
        document.getElementById('bulk-drop-zone').classList.remove('drag-over');

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
            !this.files.some(existingFile =>
                existingFile.name === newFile.name && existingFile.size === newFile.size
            )
        );

        this.files.push(...newFiles);
        this.updateFileList();
        this.showFilePreview();
    }

    updateFileList() {
        const fileList = document.getElementById('bulk-file-list');
        if (!fileList) return;

        fileList.innerHTML = '';

        this.files.forEach((file, index) => {
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item';
            fileItem.innerHTML = `
                <div class="file-info">
                    <div class="file-name">${file.name}</div>
                    <div class="file-size">${this.formatFileSize(file.size)}</div>
                </div>
                <div class="file-actions">
                    <button type="button" onclick="bulkOps.previewFile(${index})" style="padding: 5px 10px; font-size: 0.8em;">Preview</button>
                    <button type="button" onclick="bulkOps.removeFile(${index})" class="danger-button" style="padding: 5px 10px; font-size: 0.8em;">Remove</button>
                </div>
            `;
            fileList.appendChild(fileItem);
        });
    }

    showFilePreview() {
        const previewSection = document.getElementById('bulk-file-preview');
        if (previewSection) {
            previewSection.style.display = this.files.length > 0 ? 'block' : 'none';
        }
    }

    async previewFile(index) {
        const file = this.files[index];
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
        const fileList = document.getElementById('bulk-file-list');
        if (fileList) {
            fileList.parentNode.insertBefore(previewContainer, fileList.nextSibling);
        }
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

    removeFile(index) {
        this.files.splice(index, 1);
        this.updateFileList();
        this.showFilePreview();

        // Remove preview if it exists
        const existingPreview = document.querySelector('.file-preview-container');
        if (existingPreview) {
            existingPreview.remove();
        }
    }

    clearFiles() {
        this.files = [];
        this.updateFileList();
        this.showFilePreview();

        // Remove preview if it exists
        const existingPreview = document.querySelector('.file-preview-container');
        if (existingPreview) {
            existingPreview.remove();
        }

        // Clear file input
        const fileInput = document.getElementById('bulk-file-input');
        if (fileInput) fileInput.value = '';
    }

    async processFiles() {
        if (this.files.length === 0) {
            alert('Please select files to process');
            return;
        }

        const password = document.getElementById('bulk-password')?.value;
        if (!password) {
            alert('Please enter a password');
            return;
        }

        const algorithm = document.getElementById('bulk-algorithm')?.value;
        if (!algorithm) {
            alert('Please select an algorithm');
            return;
        }

        const isDecrypt = document.getElementById('bulk-operation-toggle')?.checked;

        this.isProcessing = true;
        this.results = [];

        // Show progress section
        const progressSection = document.getElementById('bulk-progress-section');
        if (progressSection) progressSection.style.display = 'block';

        // Initialize progress
        this.updateOverallProgress(0, this.files.length);
        this.initializeFileProgress();

        // Process files sequentially to avoid overwhelming the server
        for (let i = 0; i < this.files.length; i++) {
            const file = this.files[i];
            this.updateFileProgress(i, 'processing');

            try {
                const result = await this.processFile(file, password, algorithm, isDecrypt);
                this.results.push({ file, result, success: true });
                this.updateFileProgress(i, 'completed');
            } catch (error) {
                this.results.push({ file, error: error.message, success: false });
                this.updateFileProgress(i, 'error');
            }

            this.updateOverallProgress(i + 1, this.files.length);
        }

        this.isProcessing = false;
        this.showResults();
    }

    async processFile(file, password, algorithm, isDecrypt) {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('enc_password', password);
        formData.append('algorithm', algorithm);

        const endpoint = isDecrypt ? '/api/decrypt' : '/api/encrypt';

        const response = await fetch(endpoint, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Processing failed');
        }

        // Return the blob for download
        return await response.blob();
    }

    updateOverallProgress(completed, total) {
        const progressBar = document.getElementById('bulk-overall-bar');
        const progressText = document.getElementById('bulk-overall-text');

        if (progressBar) {
            const percentage = total > 0 ? (completed / total) * 100 : 0;
            progressBar.style.width = `${percentage}%`;
        }

        if (progressText) {
            progressText.textContent = `${completed} / ${total} files processed`;
        }
    }

    initializeFileProgress() {
        const progressList = document.getElementById('bulk-file-progress-list');
        if (!progressList) return;

        progressList.innerHTML = '';

        this.files.forEach((file, index) => {
            const progressItem = document.createElement('div');
            progressItem.className = 'file-progress-item';
            progressItem.innerHTML = `
                <div class="file-progress-name">${file.name}</div>
                <div class="file-progress-status" id="progress-status-${index}">Waiting</div>
            `;
            progressList.appendChild(progressItem);
        });
    }

    updateFileProgress(index, status) {
        const statusElement = document.getElementById(`progress-status-${index}`);
        if (!statusElement) return;

        statusElement.className = `file-progress-status status-${status}`;

        switch (status) {
            case 'processing':
                statusElement.textContent = 'Processing...';
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

    showResults() {
        const resultsSection = document.getElementById('bulk-results-section');
        if (!resultsSection) return;

        resultsSection.style.display = 'block';

        const resultsList = document.getElementById('bulk-results-list');
        if (!resultsList) return;

        resultsList.innerHTML = '';

        this.results.forEach((result, index) => {
            const resultItem = document.createElement('div');
            resultItem.className = 'result-item';

            const successCount = this.results.filter(r => r.success).length;
            const totalCount = this.results.length;

            if (result.success) {
                resultItem.innerHTML = `
                    <div class="result-info">
                        <div class="result-name">✅ ${result.file.name}</div>
                        <div class="result-details">Successfully processed</div>
                    </div>
                    <div class="result-actions">
                        <button type="button" onclick="bulkOps.downloadResult(${index})" style="padding: 5px 10px; font-size: 0.8em;">Download</button>
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

        // Add summary
        const summary = document.createElement('div');
        summary.style.cssText = 'padding: 15px; border-bottom: 1px solid #333; background-color: #1a1a1a; font-weight: bold;';
        summary.innerHTML = `
            <div style="color: #00ff99;">Processing Complete</div>
            <div style="font-size: 0.9em; color: #ccc; margin-top: 5px;">
                ${successCount} successful, ${totalCount - successCount} failed out of ${totalCount} files
            </div>
        `;
        resultsList.insertBefore(summary, resultsList.firstChild);
    }

    downloadResult(index) {
        const result = this.results[index];
        if (!result.success) return;

        const isDecrypt = document.getElementById('bulk-operation-toggle')?.checked;
        const algorithm = document.getElementById('bulk-algorithm')?.value;

        let filename;
        if (isDecrypt) {
            // For decryption, try to restore original filename
            filename = result.file.name.replace(/\.(aes_cbc|aes_gcm|xchacha|rsa_hybrid)\.encrypted$/, '');
        } else {
            // For encryption, add algorithm extension
            filename = `${result.file.name}.${algorithm}.encrypted`;
        }

        this.downloadBlob(result.result, filename);
    }

    downloadAllResults() {
        const successfulResults = this.results.filter(r => r.success);

        if (successfulResults.length === 0) {
            alert('No successful results to download');
            return;
        }

        successfulResults.forEach((result, index) => {
            setTimeout(() => {
                this.downloadResult(this.results.indexOf(result));
            }, index * 500); // Stagger downloads
        });
    }

    downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    reset() {
        this.clearFiles();
        this.results = [];
        this.isProcessing = false;

        // Hide sections
        const sections = ['bulk-progress-section', 'bulk-results-section'];
        sections.forEach(id => {
            const section = document.getElementById(id);
            if (section) section.style.display = 'none';
        });

        // Clear password
        const passwordField = document.getElementById('bulk-password');
        if (passwordField) passwordField.value = '';
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async populateAlgorithmDropdown() {
        try {
            const response = await fetch('/api/algorithms');
            const data = await response.json();

            if (response.ok && data.algorithms) {
                const dropdown = document.getElementById('bulk-algorithm');
                if (dropdown) {
                    dropdown.innerHTML = '';

                    for (const [key, algo] of Object.entries(data.algorithms)) {
                        if (algo.supports_file) {
                            const option = document.createElement('option');
                            option.value = key;
                            option.textContent = algo.name;
                            dropdown.appendChild(option);
                        }
                    }
                }
            }
        } catch (error) {
            console.error('Failed to load algorithms for bulk operations:', error);
        }
    }
}

// Initialize bulk operations when DOM is loaded
let bulkOps;
document.addEventListener('DOMContentLoaded', () => {
    bulkOps = new BulkOperations();
    // Make bulkOps available globally for onclick handlers
    window.bulkOps = bulkOps;
});