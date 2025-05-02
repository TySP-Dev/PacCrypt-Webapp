/**
 * Encryption module.
 * Handles cryptographic operations using Web Crypto API.
 * Implements AES-GCM encryption with PBKDF2 key derivation.
 */

// ===== Constants =====
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const PBKDF2_ITERATIONS = 200_000;
const KEY_LENGTH = 256;

// ===== Key Derivation =====
/**
 * Derives an AES-GCM key from a password using PBKDF2.
 * @param {string} password - User-supplied password.
 * @param {Uint8Array} salt - Randomly generated salt.
 * @returns {Promise<CryptoKey>} - Derived cryptographic key.
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
            iterations: PBKDF2_ITERATIONS,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: KEY_LENGTH },
        false,
        ['encrypt', 'decrypt']
    );
}

// ===== Encryption =====
/**
 * Encrypts a message using AES-GCM with a derived key.
 * @param {string} message - Plaintext message to encrypt.
 * @param {string} password - User password for key derivation.
 * @returns {Promise<string>} - Base64-encoded encrypted string.
 */
export async function encryptAdvanced(message, password) {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const key = await deriveKey(password, salt);
    const encoded = encoder.encode(message);

    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        encoded
    );

    const output = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
    output.set(salt);
    output.set(iv, salt.length);
    output.set(new Uint8Array(ciphertext), salt.length + iv.length);

    return btoa(String.fromCharCode(...output));
}

// ===== Decryption =====
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

    const salt = encrypted.slice(0, SALT_LENGTH);
    const iv = encrypted.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const ciphertext = encrypted.slice(SALT_LENGTH + IV_LENGTH);
    const key = await deriveKey(password, salt);

    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
    );

    return new TextDecoder().decode(decrypted);
}

// ===== Module Initialization =====
/**
 * Initializes the encryption module and logs its status.
 */
export function setupEncryption() {
    console.log('[Encryption] Module loaded');
}
