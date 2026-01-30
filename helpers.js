export const enc = s => new TextEncoder().encode(s);
export const dec = b => new TextDecoder().decode(b);

export const b64 = u8 => btoa(String.fromCharCode(...u8))
export const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0))