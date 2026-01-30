import { enc, dec, unb64 } from './helpers.js';

export async function decrypt(password, secret) {

    const salt = unb64(secret.salt)
    const iv = unb64(secret.iv)
    const ciphertext = unb64(secret.ciphertext)

    const baseKey = await crypto.subtle.importKey(
        'raw',
        enc(password),
        'PBKDF2',
        false,
        ['deriveKey']
    )

    const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    )

    const plainBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
    )

    return dec(new Uint8Array(plainBuf))
}