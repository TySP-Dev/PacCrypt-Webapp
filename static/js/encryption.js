// encryption.js

/**
 * Derives an AES-GCM key from a password using PBKDF2.
 * @param {string} password - User-supplied password.
 * @param {Uint8Array} salt - Randomly generated salt.
 * @returns {Promise<CryptoKey>}
 */
export async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt,
            iterations: 200_000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypts a message using AES-GCM with a derived key.
 * @param {string} message - Plaintext message to encrypt.
 * @param {string} password - User password for key derivation.
 * @returns {Promise<string>} - Base64-encoded encrypted string.
 */
export async function encryptAdvanced(message, password) {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);
    const encoded = encoder.encode(message);

    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

    const output = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
    output.set(salt);
    output.set(iv, salt.length);
    output.set(new Uint8Array(ciphertext), salt.length + iv.length);

    return btoa(String.fromCharCode(...output));
}

/**
 * Decrypts an AES-GCM encrypted string.
 * @param {string} encryptedData - Base64-encoded ciphertext.
 * @param {string} password - Password used to derive the decryption key.
 * @returns {Promise<string>} - Decrypted plaintext.
 */
export async function decryptAdvanced(encryptedData, password) {
    const encrypted = new Uint8Array(
        atob(encryptedData).split('').map(c => c.charCodeAt(0))
    );

    const salt = encrypted.slice(0, 16);
    const iv = encrypted.slice(16, 28);
    const ciphertext = encrypted.slice(28);
    const key = await deriveKey(password, salt);

    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
    );

    return new TextDecoder().decode(decrypted);
}

/**
 * Optional init logging for module diagnostics.
 */
export function setupEncryption() {
    console.log('[Encryption] Module loaded');
}
