/**
 * File operations module.
 * Handles file encryption and decryption operations.
 */

// ===== Constants =====
const CHUNK_SIZE = 1024 * 1024; // 1MB chunks

// ===== Public Interface =====
export async function encryptFile(fileInput, password) {
    const file = fileInput.files[0];
    if (!file) return;

    try {
        const encryptedChunks = await processFile(file, password, true);
        downloadEncryptedFile(encryptedChunks, file.name);
    } catch (error) {
        alert("Error encrypting file: " + error.message);
    }
}

export async function decryptFile(fileInput, password) {
    const file = fileInput.files[0];
    if (!file) return;

    try {
        const decryptedChunks = await processFile(file, password, false);
        downloadDecryptedFile(decryptedChunks, file.name);
    } catch (error) {
        alert("Error decrypting file: " + error.message);
    }
}

// ===== File Processing =====
async function processFile(file, password, isEncrypt) {
    const chunks = [];
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    let processedChunks = 0;

    for (let start = 0; start < file.size; start += CHUNK_SIZE) {
        const chunk = file.slice(start, start + CHUNK_SIZE);
        const arrayBuffer = await chunk.arrayBuffer();
        const uint8Array = new Uint8Array(arrayBuffer);
        
        const processedChunk = await processChunk(uint8Array, password, isEncrypt);
        chunks.push(processedChunk);
        
        processedChunks++;
        updateProgress(processedChunks, totalChunks);
    }

    return chunks;
}

async function processChunk(data, password, isEncrypt) {
    const payload = {
        "encryption-type": "advanced",
        operation: isEncrypt ? "encrypt" : "decrypt",
        message: Array.from(data).join(','),
        password: password
    };

    const response = await fetch("/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }

    const result = await response.json();
    return new Uint8Array(result.result.split(',').map(Number));
}

// ===== File Download =====
function downloadEncryptedFile(chunks, originalName) {
    const blob = new Blob(chunks, { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = originalName + '.encrypted';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function downloadDecryptedFile(chunks, originalName) {
    const blob = new Blob(chunks, { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = originalName.replace('.encrypted', '');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ===== Progress Tracking =====
function updateProgress(processed, total) {
    const progressBar = document.getElementById("file-progress");
    const progressText = document.getElementById("file-progress-text");
    
    if (progressBar && progressText) {
        const percent = Math.round((processed / total) * 100);
        progressBar.style.width = percent + "%";
        progressText.textContent = `Processing: ${percent}%`;
        
        if (processed === total) {
            setTimeout(() => {
                progressBar.style.width = "0%";
                progressText.textContent = "";
            }, 1000);
        }
    }
}
