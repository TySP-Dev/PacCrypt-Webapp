/**
 * File operations using the new Python backend APIs
 */

/**
 * Encrypts a full file using the backend API and downloads the encrypted version.
 */
export async function encryptFile(fileInput, password) {
    const file = fileInput.files[0];
    if (!file) return;

    const algorithm = document.getElementById("algorithm")?.value || "aes_cbc";

    try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('enc_password', password);
        formData.append('algorithm', algorithm);

        const response = await fetch('/api/encrypt', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
        }

        // Download the encrypted file
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${file.name}.${algorithm}.encrypted`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (error) {
        alert("Error encrypting file: " + error.message);
    }
}

/**
 * Decrypts a file using the backend API and downloads the decrypted version.
 */
export async function decryptFile(fileInput, password) {
    const file = fileInput.files[0];
    if (!file) return;

    try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('enc_password', password);

        const response = await fetch('/api/decrypt', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
        }

        // Download the decrypted file
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        
        // Clean up filename - remove algorithm-specific extensions
        let filename = file.name;
        const algorithms = ["aes_cbc", "aes_gcm", "xchacha", "rsa_hybrid"];
        for (const algo of algorithms) {
            filename = filename.replace(`.${algo}.encrypted`, "");
        }
        filename = filename.replace(".encrypted", "");
        
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (error) {
        alert("Error decrypting file: " + error.message);
    }
}

