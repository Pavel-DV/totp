import { enc, b64, unb64 } from './helpers.js';

const deriveWrapKey = async prf =>
    crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: PRF_SALT,
            // salt: new Uint8Array(16),
            info: enc("wrap-page-key"),
        },
        await crypto.subtle.importKey("raw", prf, "HKDF", false, ["deriveKey"]),
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );

const PRF_SALT = (() => {
    const s = localStorage.getItem("prfSalt");
    if (s) return unb64(s);

    const v = crypto.getRandomValues(new Uint8Array(32));
    localStorage.setItem("prfSalt", b64(v));
    return v;
})();

const prfBytesOnce = (() => {
    const cache = { value: null };

    return async () => {
        if (cache.value) return cache.value;

        const a = await navigator.credentials.get({
            publicKey: {
                challenge: crypto.getRandomValues(new Uint8Array(32)),
                userVerification: "required",
                extensions: { prf: { eval: { first: PRF_SALT } } },
            },
        });

        const prf = a.getClientExtensionResults().prf?.results?.first;

        if (!prf) {
            await navigator.credentials.create({
                publicKey: {
                    challenge: crypto.getRandomValues(new Uint8Array(32)),
                    rp: { name: "Local Protected Media" },
                    user: {
                        id: crypto.getRandomValues(new Uint8Array(32)),
                        name: "totp-user",
                        displayName: "Totp User"
                    },
                    pubKeyCredParams: [
                        { type: "public-key", alg: -7 },
                        { type: "public-key", alg: -257 }
                    ],
                    authenticatorSelection: {
                        authenticatorAttachment: "platform",
                        userVerification: "required"
                    },
                    extensions: { prf: {} }
                }
            });

            // iOS Safari needs a reload after create
            // location.reload();

            return await prfBytesOnce();
        }

        cache.value = prf;
        return prf;
    };
})();

async function wrapKey(rawBytes) {
    const key = await deriveWrapKey(await prfBytesOnce());
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        rawBytes
    );

    localStorage.setItem("wrappedKeyIv", b64(iv));
    localStorage.setItem("wrappedKeyData", b64(new Uint8Array(data)));
}

export async function unwrapKey() {
    const ivB64 = localStorage.getItem("wrappedKeyIv");
    const dataB64 = localStorage.getItem("wrappedKeyData");

    // first run: no wrapped key → ask user
    if (!ivB64 || !dataB64) {
        const password = prompt("Password");
        if (!password) throw new Error("No password");

        const raw = enc(password);
        await wrapKey(raw);
        return raw;
    }

    // normal path: WebAuthn unlock
    const key = await deriveWrapKey(await prfBytesOnce());
    const iv = unb64(ivB64);
    const data = unb64(dataB64);

    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return new Uint8Array(plain);
}