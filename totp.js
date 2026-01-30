const base32ToBytes = secretBase32 => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    const bits = secretBase32
        .replace(/=+$/, '')
        .toUpperCase()
        .split('')
        .map(char => alphabet.indexOf(char))
        .filter(value => value >= 0)
        .map(value => value.toString(2).padStart(5, '0'))
        .join('')

    return new Uint8Array(
        bits
            .match(/.{8}/g)
            .map(byte => parseInt(byte, 2))
    )
}

export const generateTotpCode = async (secretBase32, timeStep) => {
    const counterBuffer = new ArrayBuffer(8)
    new DataView(counterBuffer).setBigUint64(0, BigInt(timeStep))

    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        base32ToBytes(secretBase32),
        { name: 'HMAC', hash: 'SHA-1' },
        false,
        ['sign']
    )

    const hmacResult = new Uint8Array(
        await crypto.subtle.sign('HMAC', cryptoKey, counterBuffer)
    )

    const offset = hmacResult[hmacResult.length - 1] & 15
    const binaryCode =
        ((hmacResult[offset] & 127) << 24) |
        ((hmacResult[offset + 1] & 255) << 16) |
        ((hmacResult[offset + 2] & 255) << 8) |
        (hmacResult[offset + 3] & 255)

    return String(binaryCode % 1_000_000).padStart(6, '0')
}
