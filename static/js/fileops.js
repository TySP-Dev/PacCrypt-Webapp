// fileops.js

import { encryptAdvanced, decryptAdvanced } from './encryption.js';

/**
 * Encrypts the selected file and triggers download of the encrypted version.
 * @param {HTMLInputElement} fileInput - The input element of type 'file'.
 * @param {string} password - Password for encryption.
 */
export function encryptFile(fileInput, password) {
    if (!fileInput.files.length) {
        alert("Please select a file!");
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = async (e) => {
        const rawBytes = new Uint8Array(e.target.result);
        const base64 = btoa(String.fromCharCode(...rawBytes));
        const encrypted = await encryptAdvanced(base64, password);
        downloadFile(encrypted, file.name + ".enc");
    };

    reader.readAsArrayBuffer(file);
}

/**
 * Decrypts the selected encrypted file and triggers download of the original.
 * @param {HTMLInputElement} fileInput - The input element of type 'file'.
 * @param {string} password - Password for decryption.
 */
export function decryptFile(fileInput, password) {
    if (!fileInput.files.length) {
        alert("Please select a file!");
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = async (e) => {
        try {
            const encryptedText = e.target.result;
            const base64Decrypted = await decryptAdvanced(encryptedText, password);
            const byteArray = new Uint8Array(
                [...atob(base64Decrypted)].map(c => c.charCodeAt(0))
            );
            downloadFileBinary(byteArray, file.name.replace(/\.enc$/, ''));
        } catch (err) {
            console.error("[Decryption Error]", err);
            alert("Decryption failed: wrong password or corrupted file.");
        }
    };

    reader.readAsText(file);
}

/**
 * Downloads a text-based file (encrypted string).
 * @param {string} content - The file content to download.
 * @param {string} filename - Desired name for the downloaded file.
 */
function downloadFile(content, filename) {
    const blob = new Blob([content], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();

    URL.revokeObjectURL(url);
}

/**
 * Downloads a binary file (Uint8Array).
 * @param {Uint8Array} byteArray - The binary content.
 * @param {string} filename - Desired name for the downloaded file.
 */
function downloadFileBinary(byteArray, filename) {
    const blob = new Blob([byteArray], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();

    URL.revokeObjectURL(url);
}
