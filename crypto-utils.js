const getConstant = (idx) => {
    const c = [
        [77, 121, 83, 117, 112, 101, 114, 83, 101, 99, 114, 101, 116, 75, 51, 121],
        [73, 110, 105, 116, 105, 97, 108, 86, 101, 99, 116, 111, 114, 49, 50, 51]
    ];
    return String.fromCharCode(...c[idx]);
};

const AES_KEY = getConstant(0);
const AES_IV = getConstant(1);

async function encryptData(data) {
    try {
        const encoder = new TextEncoder();
        const keyData = encoder.encode(AES_KEY);
        const ivData = encoder.encode(AES_IV);

        const cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'AES-CBC', length: 128 },
            false,
            ['encrypt']
        );

        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: 'AES-CBC', iv: ivData },
            cryptoKey,
            encoder.encode(data)
        );
        return btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedBuffer)));
    } catch (error) {
        console.error("Encryption error:", error);
        return null;
    }
}

async function generateHmac(data) {
    try {
        const encoder = new TextEncoder();
        const keyData = encoder.encode(AES_KEY);

        const cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        const signatureBuffer = await window.crypto.subtle.sign(
            'HMAC',
            cryptoKey,
            encoder.encode(data)
        );
        return Array.from(new Uint8Array(signatureBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (error) {
        console.error("HMAC generation error:", error);
        return null;
    }
} 
