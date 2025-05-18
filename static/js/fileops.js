import { deriveKey } from "./encryption.js";  // assuming shared deriveKey()

const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const KEY_LENGTH = 256;

/**
 * Encrypts a full file and downloads the encrypted version.
 */
export async function encryptFile(fileInput, password) {
    const file = fileInput.files[0];
    if (!file) return;

    try {
        const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
        const key = await deriveKey(password, salt);
        const fileBuffer = new Uint8Array(await file.arrayBuffer());

        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            fileBuffer
        );

        const ctBytes = new Uint8Array(ciphertext);
        const result = new Uint8Array(salt.length + iv.length + ctBytes.length);
        result.set(salt);
        result.set(iv, salt.length);
        result.set(ctBytes, salt.length + iv.length);

        const blob = new Blob([result], { type: "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = file.name + ".encrypted";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (error) {
        alert("Error encrypting file: " + error.message);
    }
}

export async function decryptFile(fileInput, password) {
    const file = fileInput.files[0];
    if (!file) return;

    try {
        const data = new Uint8Array(await file.arrayBuffer());
        const salt = data.slice(0, SALT_LENGTH);
        const iv = data.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
        const ciphertext = data.slice(SALT_LENGTH + IV_LENGTH);
        const key = await deriveKey(password, salt);

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            key,
            ciphertext
        );

        const blob = new Blob([decrypted], { type: "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = file.name.replace(".encrypted", "");
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
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
