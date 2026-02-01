/**
 * Helper for cryptographic hashing using Web Crypto API.
 */
const hash = async (algo, str) => {
    if (!window.crypto || !window.crypto.subtle) return "Secure context required";
    const msg = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest(algo, msg);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
};

const crcTable = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    crcTable[i] = c;
}

const crc32 = (str) => {
    const bytes = new TextEncoder().encode(str);
    let crc = -1;
    for (let i = 0; i < bytes.length; i++) crc = (crc >>> 8) ^ crcTable[(crc ^ bytes[i]) & 0xFF];
    return ((crc ^ -1) >>> 0).toString(16).padStart(8, '0');
};

const adler32 = (str) => {
    const bytes = new TextEncoder().encode(str);
    let a = 1, b = 0;
    for (let i = 0; i < bytes.length; i++) {
        a = (a + bytes[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (((b << 16) | a) >>> 0).toString(16).padStart(8, '0');
};

/**
 * AES-GCM Implementation with PBKDF2 Key Derivation.
 */
const getAesKey = async (password, salt) => {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
};

const aesEncrypt = async (str, password = "OmniEncoder") => {
    try {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await getAesKey(password, salt);
        const enc = new TextEncoder().encode(str);
        const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, enc);

        // Combine Salt + IV + Ciphertext and Base64 encode
        const combined = new Uint8Array(salt.length + iv.length + cipher.byteLength);
        combined.set(salt);
        combined.set(iv, salt.length);
        combined.set(new Uint8Array(cipher), salt.length + iv.length);
        return btoa(String.fromCharCode(...combined));
    } catch (e) { return "Encryption Error"; }
};

const aesDecrypt = async (str, password = "OmniEncoder") => {
    try {
        const raw = Uint8Array.from(atob(str), c => c.charCodeAt(0));
        const salt = raw.slice(0, 16);
        const iv = raw.slice(16, 28);
        const cipher = raw.slice(28);
        const key = await getAesKey(password, salt);
        const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, cipher);
        return new TextDecoder().decode(dec);
    } catch (e) { return "Invalid Password or Data"; }
};

/**
 * HMAC-SHA256 Signing for JWTs.
 */
const hmacSign = async (key, data) => {
    if (!window.crypto || !window.crypto.subtle) return "Secure Context Required";
    try {
        const enc = new TextEncoder();
        const cryptoKey = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const signature = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(data));
        return btoa(String.fromCharCode(...new Uint8Array(signature)))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    } catch (e) { return "Signing Error"; }
};

/**
 * Collection of encoder definitions.
 * Each encoder has a name, description, and a function `fn` that takes a string and returns the encoded string.
 */
const encoders = {
    base64: { name: "Base64", desc: "Binary-to-text encoding scheme", fn: (str) => { try { const bytes = new TextEncoder().encode(str); const binary = []; for (let i = 0; i < bytes.length; i++) binary.push(String.fromCharCode(bytes[i])); return btoa(binary.join('')); } catch (e) { return "Error"; } } },
    hex: { name: "Hexadecimal", desc: "Base-16 ASCII representation", fn: (str) => { const bytes = new TextEncoder().encode(str); const res = []; for (let i = 0; i < bytes.length; i++) res.push(bytes[i].toString(16).padStart(2, '0')); return res.join(' '); } },
    octal: { name: "Octal", desc: "Base-8 number system", fn: (str) => { const bytes = new TextEncoder().encode(str); const res = []; for (let i = 0; i < bytes.length; i++) res.push(bytes[i].toString(8).padStart(3, '0')); return res.join(' '); } },
    binary: { name: "Binary", desc: "8-bit binary stream", fn: (str) => { const bytes = new TextEncoder().encode(str); const res = []; for (let i = 0; i < bytes.length; i++) res.push(bytes[i].toString(2).padStart(8, '0')); return res.join(' '); } },
    rot13: { name: "ROT13", desc: "Simple letter substitution", fn: (str) => { return str.replace(/[a-zA-Z]/g, function (c) { return String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26); }); } },
    leet: { name: "1337 Speak", desc: "Alphanumeric substitution", fn: (str) => { const m = { 'a': '4', 'b': '8', 'e': '3', 'g': '9', 'l': '1', 'o': '0', 's': '5', 't': '7', 'z': '2', 'A': '4', 'B': '8', 'E': '3', 'G': '9', 'L': '1', 'O': '0', 'S': '5', 'T': '7', 'Z': '2' }; return str.split('').map(c => m[c] || c).join(''); } },
    atbash: { name: "Atbash", desc: "Reversed alphabet cipher", fn: (str) => { return str.replace(/[a-zA-Z]/g, (c) => { const k = c.charCodeAt(0); if (k >= 65 && k <= 90) return String.fromCharCode(90 - (k - 65)); if (k >= 97 && k <= 122) return String.fromCharCode(122 - (k - 97)); return c; }); } },
    rot47: { name: "ROT47", desc: "ASCII shift-47 cipher", fn: (str) => str.replace(/[!-~]/g, function (c) { return String.fromCharCode(33 + ((c.charCodeAt(0) + 14) % 94)); }) },
    unicode: { name: "Unicode Escape", desc: "JS/Java escape sequences", fn: (str) => str.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('') },
    tap: { name: "Tap Code", desc: "Polybius square (C=K)", fn: (str) => { const p = "abcdefghijlmnopqrstuvwxyz"; return str.toLowerCase().split('').map(c => { if (c === 'k') c = 'c'; const i = p.indexOf(c); if (i === -1) return c; return (Math.floor(i / 5) + 1) + '' + ((i % 5) + 1); }).join(' '); } },
    sha1: { name: "SHA-1", desc: "Secure Hash Algorithm 1", fn: (str) => hash('SHA-1', str), reversible: false },
    sha256: { name: "SHA-256", desc: "Secure Hash Algorithm 256", fn: (str) => hash('SHA-256', str), reversible: false },
    sha512: { name: "SHA-512", desc: "Secure Hash Algorithm 512", fn: (str) => hash('SHA-512', str), reversible: false },
    crc32: { name: "CRC32", desc: "Cyclic Redundancy Check", fn: (str) => crc32(str), reversible: false },
    adler32: { name: "Adler-32", desc: "Checksum algorithm (zlib)", fn: (str) => adler32(str), reversible: false },
    base32: { name: "Base32", desc: "RFC 4648 Base32 encoding", fn: (str) => { const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; const bytes = new TextEncoder().encode(str); let output = ""; let val = 0; let bits = 0; for (let i = 0; i < bytes.length; i++) { val = (val << 8) | bytes[i]; bits += 8; while (bits >= 5) { output += a[(val >>> (bits - 5)) & 31]; bits -= 5; } } if (bits > 0) output += a[(val << (5 - bits)) & 31]; while (output.length % 8 !== 0) output += "="; return output; } },
    base58: { name: "Base58", desc: "Bitcoin/Crypto encoding", fn: (str) => { const A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; const b = new TextEncoder().encode(str); let x = 0n; for (let i = 0; i < b.length; i++) x = x * 256n + BigInt(b[i]); const res = []; while (x > 0n) { res.push(A[Number(x % 58n)]); x /= 58n; } for (let i = 0; i < b.length && b[i] === 0; i++) res.push('1'); return res.reverse().join(''); } },
    vigenere: { name: "Vigenère Cipher", desc: "Polyalphabetic substitution", fn: (str, key) => { if (!key) return "Key required"; const k = key.toUpperCase().replace(/[^A-Z]/g, ''); if (!k) return str; let ki = 0; return str.replace(/[a-zA-Z]/g, c => { const base = c >= 'a' ? 97 : 65; const shift = k.charCodeAt(ki++ % k.length) - 65; return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base); }); } },
    jwt: {
        name: "JWT Builder", desc: "Sign JSON as HS256 Token", fn: async (str, key) => {
            const k = key || "OmniEncoder";
            try {
                let payload;
                try { payload = JSON.parse(str); }
                catch (e) { payload = { sub: "user", data: str, iat: Math.floor(Date.now() / 1000) }; }

                const header = { alg: "HS256", typ: "JWT" };
                const b64 = (obj) => {
                    const bytes = new TextEncoder().encode(JSON.stringify(obj));
                    const bin = []; for (let i = 0; i < bytes.length; i++) bin.push(String.fromCharCode(bytes[i]));
                    return btoa(bin.join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
                };
                const unsigned = `${b64(header)}.${b64(payload)}`;
                return `${unsigned}.${await hmacSign(k, unsigned)}`;
            } catch (e) { return "Error generating JWT"; }
        }
    },
    aes: { name: "AES-GCM", desc: "256-bit Encryption (PBKDF2)", fn: (str, pass) => aesEncrypt(str, pass) },
    nato: {
        name: "NATO Phonetic", desc: "Radiotelephony spelling", fn: (str) => {
            const n = { 'a': 'alpha', 'b': 'bravo', 'c': 'charlie', 'd': 'delta', 'e': 'echo', 'f': 'foxtrot', 'g': 'golf', 'h': 'hotel', 'i': 'india', 'j': 'juliett', 'k': 'kilo', 'l': 'lima', 'm': 'mike', 'n': 'november', 'o': 'oscar', 'p': 'papa', 'q': 'quebec', 'r': 'romeo', 's': 'sierra', 't': 'tango', 'u': 'uniform', 'v': 'victor', 'w': 'whiskey', 'x': 'x-ray', 'y': 'yankee', 'z': 'zulu', '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three', '4': 'Four', '5': 'Five', '6': 'Six', '7': 'Seven', '8': 'Eight', '9': 'Nine' };
            return str.split('').map(c => {
                const lower = c.toLowerCase();
                if (!n[lower]) return c;
                const word = n[lower];
                // Preserve case: A -> ALPHA, a -> alpha
                return (c === lower) ? word : word.toUpperCase();
            }).join(' ');
        }
    },
    htmlEnt: { name: "HTML Entities", desc: "Safe characters for web", fn: (str) => { return str.replace(/[\u00A0-\u9999<>\&]/g, (i) => '&#' + i.charCodeAt(0) + ';'); } },
    url: { name: "URL Encoded", desc: "Percent-encoding for URLs", fn: (str) => encodeURIComponent(str) },
    reverse: { name: "Reverse", desc: "Reversed character order", fn: (str) => str.split('').reverse().join('') },
    ascii: { name: "ASCII", desc: "Decimal code points", fn: (str) => { const res = []; for (let i = 0; i < str.length; i++) res.push(str.charCodeAt(i)); return res.join(', '); } },
    morse: { name: "Morse Code", desc: "Telecommunication encoding", fn: (str) => { const m = { 'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', '0': '-----', ' ': '/', '.': '.-.-.-', ',': '--..--', '?': '..--..', '!': '-.-.--', '@': '.--.-.', '-': '-....-' }; return str.toUpperCase().split('').map(c => m[c] || c).join(' '); } },
    quotedPrintable: { name: "Quoted-Printable", desc: "MIME encoding (=XX)", fn: (str) => str.split('').map(c => { const code = c.charCodeAt(0); return (code >= 33 && code <= 126 && c !== '=') ? c : '=' + code.toString(16).toUpperCase().padStart(2, '0'); }).join('') },
    bacon: { name: "Bacon Cipher", desc: "Steganography (A/B)", fn: (str) => { const map = { 'A': 'aaaaa', 'B': 'aaaab', 'C': 'aaaba', 'D': 'aaabb', 'E': 'aabaa', 'F': 'aabab', 'G': 'aabba', 'H': 'aabbb', 'I': 'abaaa', 'J': 'abaab', 'K': 'ababa', 'L': 'ababb', 'M': 'abbaa', 'N': 'abbab', 'O': 'abbba', 'P': 'abbbb', 'Q': 'baaaa', 'R': 'baaab', 'S': 'baaba', 'T': 'baabb', 'U': 'babaa', 'V': 'babab', 'W': 'babba', 'X': 'babbb', 'Y': 'bbaaa', 'Z': 'bbaab' }; return str.toUpperCase().replace(/[A-Z]/g, c => map[c] || c); } },
    dert: { name: "Dert Cipher", desc: "Shifted Base-4 (D,e,r,t)", fn: (str) => { const m = ['D', 'e', 'r', 't']; const bytes = new TextEncoder().encode(str); const res = []; for (let i = 0; i < bytes.length; i++) { let b = (bytes[i] + i) % 256; const s = i % 4; res.push(m[(((b >> 6) & 3) + s) % 4] + m[(((b >> 4) & 3) + s) % 4] + m[(((b >> 2) & 3) + s) % 4] + m[((b & 3) + s) % 4]); } return res.join(''); } },
    caesar: { name: "Caesar Cipher", desc: "Variable rotation (default: 3)", fn: (str, shift = 3) => { const s = parseInt(shift) || 3; return str.replace(/[a-zA-Z]/g, c => { const base = c >= 'a' ? 97 : 65; return String.fromCharCode(((c.charCodeAt(0) - base + s + 26) % 26) + base); }); } },
    xor: { name: "XOR Cipher", desc: "Bitwise XOR with key (default: 42)", fn: (str, key = "42") => { const k = parseInt(key) || 42; return str.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ k)).join(''); } },
    railfence: { name: "Rail Fence", desc: "Zigzag transposition cipher", fn: (str, rails = 3) => { const r = parseInt(rails) || 3; if (r <= 1) return str; const fence = Array(r).fill().map(() => []); let rail = 0, dir = 1; for (const c of str) { fence[rail].push(c); rail += dir; if (rail === 0 || rail === r - 1) dir *= -1; } return fence.flat().join(''); } },
    a1z26: { name: "A1Z26", desc: "Letters to numbers (A=1)", fn: (str) => str.toLowerCase().split('').map(c => { if (c >= 'a' && c <= 'z') return c.charCodeAt(0) - 96; return c; }).join('-').replace(/--+/g, ' ').replace(/-$/, '') }
};

/**
 * Collection of decoder definitions.
 * Each decoder takes a string and returns the decoded string.
 * Some decoders attempt to handle errors gracefully or return specific error messages.
 */
const decoders = {
    binary: (str) => {
        if (/[\s,\-]/.test(str)) {
            const parts = str.split(/[\s,\-]+/).filter(x => /^[01]+$/.test(x));
            if (parts.length === 0 && str.trim().length > 0) return "Invalid Binary";
            const bytes = new Uint8Array(parts.length);
            for (let i = 0; i < parts.length; i++) bytes[i] = parseInt(parts[i], 2);
            return new TextDecoder().decode(bytes);
        }
        const clean = str.replace(/[^01]/g, '');
        if (clean.length === 0 && str.trim().length > 0) return "Invalid Binary";
        const bytes = new Uint8Array(Math.floor(clean.length / 8));
        for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 8, (i + 1) * 8), 2);
        return new TextDecoder().decode(bytes);
    },
    octal: (str) => {
        if (/[\s,\-]/.test(str)) {
            const parts = str.split(/[\s,\-]+/).filter(x => /^[0-7]+$/.test(x));
            if (parts.length === 0 && str.trim().length > 0) return "Invalid Octal";
            const bytes = new Uint8Array(parts.length);
            for (let i = 0; i < parts.length; i++) bytes[i] = parseInt(parts[i], 8);
            return new TextDecoder().decode(bytes);
        }
        const clean = str.replace(/[^0-7]/g, '');
        if (clean.length === 0 && str.trim().length > 0) return "Invalid Octal";
        const bytes = new Uint8Array(Math.floor(clean.length / 3));
        for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 3, (i + 1) * 3), 8);
        return new TextDecoder().decode(bytes);
    },
    hex: (str) => {
        if (/[\s,\-]/.test(str)) {
            const parts = str.split(/[\s,\-]+/).filter(x => /^(0x)?[0-9A-Fa-f]+$/i.test(x));
            if (parts.length === 0 && str.trim().length > 0) return "Invalid Hex";
            const bytes = new Uint8Array(parts.length);
            for (let i = 0; i < parts.length; i++) bytes[i] = parseInt(parts[i], 16);
            return new TextDecoder().decode(bytes);
        }
        const clean = str.replace(/[^0-9A-Fa-f]/g, '');
        if (clean.length === 0 && str.trim().length > 0) return "Invalid Hex";
        const bytes = new Uint8Array(Math.floor(clean.length / 2));
        for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, (i + 1) * 2), 16);
        return new TextDecoder().decode(bytes);
    },
    base64: (str) => {
        try {
            const bin = atob(str);

            // Simple Magic Number check for Images (PNG, JPG, GIF)
            const len = bin.length;
            if (len > 4) {
                const c1 = bin.charCodeAt(0), c2 = bin.charCodeAt(1), c3 = bin.charCodeAt(2);
                // PNG (89 50 4E), JPG (FF D8), GIF (47 49 46)
                if ((c1 === 0x89 && c2 === 0x50 && c3 === 0x4E) || (c1 === 0xFF && c2 === 0xD8) || (c1 === 0x47 && c2 === 0x49 && c3 === 0x46)) {
                    // Return an HTML string that the UI will render
                    return `<div class="flex flex-col items-center gap-2"><img src="data:image/auto;base64,${str}" class="max-h-48 rounded border border-white/20 shadow-lg" /><span class="text-[10px] text-gray-500">Image Detected</span></div>`;
                }
            }

            const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
            return new TextDecoder().decode(bytes);
        } catch (e) {
            try { return atob(str); } catch (e2) { return "Invalid Base64"; }
        }
    },
    rot47: (str) => encoders.rot47.fn(str),
    unicode: (str) => str.replace(/\\u([0-9a-fA-F]{4})/g, (m, p1) => String.fromCharCode(parseInt(p1, 16))),
    tap: (str) => { const p = "abcdefghijlmnopqrstuvwxyz"; return str.split(' ').map(c => { if (c.length !== 2 || isNaN(c)) return c; const r = parseInt(c[0]) - 1; const k = parseInt(c[1]) - 1; if (r < 0 || r > 4 || k < 0 || k > 4) return c; return p[r * 5 + k]; }).join(''); },
    rot13: (str) => encoders.rot13.fn(str),
    reverse: (str) => encoders.reverse.fn(str),
    url: (str) => decodeURIComponent(str),
    atbash: (str) => encoders.atbash.fn(str),
    htmlEnt: (str) => {
        if (str.length > 500000 && !confirm("Input is larger than 500KB. Decoding HTML Entities may crash the browser. Are you sure you want to proceed?")) return "Aborted by user";
        const txt = document.createElement("textarea"); txt.innerHTML = str; return txt.value;
    },
    ascii: (str) => {
        const parts = str.split(/[\s,]+/).filter(Boolean);
        if (parts.some(p => isNaN(p))) return "Invalid ASCII";
        return parts.map(c => String.fromCharCode(c)).join('');
    },
    nato: (str) => {
        const r = { 'alpha': 'a', 'bravo': 'b', 'charlie': 'c', 'delta': 'd', 'echo': 'e', 'foxtrot': 'f', 'golf': 'g', 'hotel': 'h', 'india': 'i', 'juliett': 'j', 'kilo': 'k', 'lima': 'l', 'mike': 'm', 'november': 'n', 'oscar': 'o', 'papa': 'p', 'quebec': 'q', 'romeo': 'r', 'sierra': 's', 'tango': 't', 'uniform': 'u', 'victor': 'v', 'whiskey': 'w', 'x-ray': 'x', 'yankee': 'y', 'zulu': 'z', 'zero': '0', 'one': '1', 'two': '2', 'three': '3', 'four': '4', 'five': '5', 'six': '6', 'seven': '7', 'eight': '8', 'nine': '9' };
        return str.split(' ').map(w => {
            const k = w.toLowerCase();
            if (!r[k]) return w;
            const val = r[k];
            // Heuristic: If word is ALL CAPS or Title Case, return Upper Case char. Else Lower.
            return (w === w.toUpperCase() || (w[0] === w[0].toUpperCase() && w.length > 1)) ? val.toUpperCase() : val;
        }).join('');
    },
    morse: (str) => { const r = { '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z', '.----': '1', '..---': '2', '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9', '-----': '0', '/': ' ', '.-.-.-': '.', '--..--': ',', '..--..': '?', '-.-.--': '!', '.--.-.': '@', '-....-': '-' }; return str.split(' ').map(c => r[c] || c).join(''); },
    leet: (str) => { const r = { '4': 'a', '8': 'b', '3': 'e', '9': 'g', '1': 'l', '0': 'o', '5': 's', '7': 't', '2': 'z' }; return str.split('').map(c => r[c] || c).join(''); },
    sha1: (str) => /^[a-f0-9]{40}$/i.test(str.trim()) ? "Format: Valid SHA-1 (Click to Verify)" : "Invalid SHA-1 Format",
    sha256: (str) => /^[a-f0-9]{64}$/i.test(str.trim()) ? "Format: Valid SHA-256 (Click to Verify)" : "Invalid SHA-256 Format",
    sha512: (str) => /^[a-f0-9]{128}$/i.test(str.trim()) ? "Format: Valid SHA-512 (Click to Verify)" : "Invalid SHA-512 Format",
    crc32: (str) => /^[a-f0-9]{8}$/i.test(str.trim()) ? "Format: Valid CRC32 (Click to Verify)" : "Invalid CRC32 Format",
    adler32: (str) => /^[a-f0-9]{8}$/i.test(str.trim()) ? "Format: Valid Adler-32 (Click to Verify)" : "Invalid Adler-32 Format",
    base32: (str) => { const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let clean = str.toUpperCase().replace(/[^A-Z2-7]/g, ""); if (clean.length === 0) return "Invalid Base32"; let output = []; let val = 0; let bits = 0; for (let i = 0; i < clean.length; i++) { val = (val << 5) | a.indexOf(clean[i]); bits += 5; if (bits >= 8) { output.push((val >>> (bits - 8)) & 255); bits -= 8; } } return new TextDecoder().decode(new Uint8Array(output)); },
    base58: (str) => { const A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; let x = 0n; for (let i = 0; i < str.length; i++) { const idx = A.indexOf(str[i]); if (idx === -1) return "Invalid Base58"; x = x * 58n + BigInt(idx); } const b = []; while (x > 0n) { b.push(Number(x % 256n)); x /= 256n; } for (let i = 0; i < str.length && str[i] === '1'; i++) b.push(0); return new TextDecoder().decode(new Uint8Array(b.reverse())); },
    vigenere: (str, key) => { if (!key) return "Key required"; const k = key.toUpperCase().replace(/[^A-Z]/g, ''); if (!k) return str; let ki = 0; return str.replace(/[a-zA-Z]/g, c => { const base = c >= 'a' ? 97 : 65; const shift = k.charCodeAt(ki++ % k.length) - 65; return String.fromCharCode(((c.charCodeAt(0) - base - shift + 26) % 26) + base); }); },
    jwt: (str) => { try { const parts = str.split('.'); if (parts.length !== 3) return "Invalid JWT format"; const fix = s => s.replace(/-/g, '+').replace(/_/g, '/').padEnd(s.length + (4 - s.length % 4) % 4, '='); const header = JSON.parse(atob(fix(parts[0]))); const payload = JSON.parse(atob(fix(parts[1]))); return JSON.stringify({ header, payload }, null, 2); } catch (e) { return "Invalid JWT"; } },
    aes: (str, pass) => aesDecrypt(str, pass),
    quotedPrintable: (str) => str.replace(/=([0-9A-F]{2})/gi, (m, p1) => String.fromCharCode(parseInt(p1, 16))),
    bacon: (str) => { const map = { 'aaaaa': 'A', 'aaaab': 'B', 'aaaba': 'C', 'aaabb': 'D', 'aabaa': 'E', 'aabab': 'F', 'aabba': 'G', 'aabbb': 'H', 'abaaa': 'I', 'abaab': 'J', 'ababa': 'K', 'ababb': 'L', 'abbaa': 'M', 'abbab': 'N', 'abbba': 'O', 'abbbb': 'P', 'baaaa': 'Q', 'baaab': 'R', 'baaba': 'S', 'baabb': 'T', 'babaa': 'U', 'babab': 'V', 'babba': 'W', 'babbb': 'X', 'bbaaa': 'Y', 'bbaab': 'Z' }; return str.toLowerCase().replace(/[ab]{5}/g, m => map[m] || m); },
    dert: (str) => { const m = { 'D': 0, 'e': 1, 'r': 2, 't': 3 }; const c = str.replace(/[^Dert]/g, ''); if (c.length % 4 !== 0) return "Invalid Dert"; const b = new Uint8Array(c.length / 4); for (let i = 0; i < b.length; i++) { const s = i % 4; const idx = i * 4; const v1 = (m[c[idx]] - s + 4) % 4; const v2 = (m[c[idx + 1]] - s + 4) % 4; const v3 = (m[c[idx + 2]] - s + 4) % 4; const v4 = (m[c[idx + 3]] - s + 4) % 4; const val = (v1 << 6) | (v2 << 4) | (v3 << 2) | v4; b[i] = (val - i % 256 + 256) % 256; } return new TextDecoder().decode(b); },
    caesar: (str, shift = 3) => { const s = parseInt(shift) || 3; return str.replace(/[a-zA-Z]/g, c => { const base = c >= 'a' ? 97 : 65; return String.fromCharCode(((c.charCodeAt(0) - base - s + 26) % 26) + base); }); },
    xor: (str, key = "42") => { const k = parseInt(key) || 42; return str.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ k)).join(''); },
    railfence: (str, rails = 3) => { const r = parseInt(rails) || 3; if (r <= 1) return str; const n = str.length; const cycle = 2 * (r - 1); const result = new Array(n); let idx = 0; for (let row = 0; row < r; row++) { for (let i = row; i < n; i += cycle) { result[i] = str[idx++]; if (row > 0 && row < r - 1) { const next = i + cycle - 2 * row; if (next < n) result[next] = str[idx++]; } } } return result.join(''); },
    a1z26: (str) => { return str.split(/[\s-]+/).map(p => { const n = parseInt(p); if (!isNaN(n) && n >= 1 && n <= 26) return String.fromCharCode(96 + n); return p; }).join(''); },
    default: (str) => str
};

const inputEl = document.getElementById('input-text');
const gridEl = document.getElementById('encoders-grid');
const chainResultEl = document.getElementById('chain-result');
const chainVisualizerEl = document.getElementById('chain-visualizer');
const chainStepCountEl = document.getElementById('chain-step-count');
const statWords = document.getElementById('stat-words');
const statLines = document.getElementById('stat-lines');
const statBytes = document.getElementById('stat-bytes');
const bestMatchContainer = document.getElementById('best-match-container');
const bestMatchName = document.getElementById('best-match-name');
const bestMatchResult = document.getElementById('best-match-result');

// ============================================
// OmniEncoder Client-Side API
// ============================================
// Usage:
//   OmniEncoder.encode('hello', 'base64')  -> Promise<string>
//   OmniEncoder.decode('aGVsbG8=', 'base64') -> Promise<string>
//   OmniEncoder.chain('hello', ['base64', 'hex']) -> Promise<string>
//   OmniEncoder.detect('aGVsbG8=') -> Promise<{type, confidence, decoded}>
//   OmniEncoder.getAvailableEncoders() -> string[]
//   OmniEncoder.on('complete', callback) -> void
//   OmniEncoder.results -> current results object
// ============================================

window.OmniEncoder = {
    version: '3.1.0',

    // Current processing results (legacy compatibility)
    get results() { return window.omniResults; },
    get isComplete() { return window.omniComplete; },

    // Get list of available encoders
    getAvailableEncoders() {
        return Object.keys(encoders).map(key => ({
            id: key,
            name: encoders[key].name,
            description: encoders[key].desc,
            reversible: encoders[key].reversible !== false
        }));
    },

    // Encode a string with a specific encoder
    async encode(text, encoderKey, options = {}) {
        if (!encoders[encoderKey]) {
            throw new Error(`Unknown encoder: ${encoderKey}`);
        }
        return await encoders[encoderKey].fn(text, options.key || options.password);
    },

    // Decode a string with a specific decoder
    async decode(text, decoderKey, options = {}) {
        if (!decoders[decoderKey]) {
            throw new Error(`Unknown decoder: ${decoderKey}`);
        }
        return await decoders[decoderKey](text, options.key || options.password);
    },

    // Run a chain of encoders/decoders
    async chain(text, sequence, mode = 'encode') {
        let current = text;
        const steps = mode === 'encode' ? sequence : [...sequence].reverse();
        const fn = mode === 'encode' ? encoders : decoders;

        for (const key of steps) {
            if (!fn[key]) continue;
            try {
                current = mode === 'encode'
                    ? await fn[key].fn(current)
                    : await fn[key](current);
            } catch (e) {
                return { error: `Chain broke at ${key}: ${e.message}`, lastOutput: current };
            }
        }
        return current;
    },

    // Auto-detect encoding and return best match
    async detect(text) {
        const best = await findBestMatch(text);
        if (!best) return null;
        return {
            type: best.key,
            name: encoders[best.key]?.name || best.key,
            confidence: Math.min(Math.round(best.score), 100),
            decoded: best.decoded
        };
    },

    // Hash a string
    async hash(text, algorithm = 'sha256') {
        const algo = algorithm.toLowerCase().replace('-', '');
        if (!encoders[algo]) {
            throw new Error(`Unknown hash algorithm: ${algorithm}`);
        }
        return await encoders[algo].fn(text);
    },

    // Event listeners
    _listeners: { complete: [], error: [] },

    on(event, callback) {
        if (this._listeners[event]) {
            this._listeners[event].push(callback);
        }
    },

    off(event, callback) {
        if (this._listeners[event]) {
            this._listeners[event] = this._listeners[event].filter(cb => cb !== callback);
        }
    },

    _emit(event, data) {
        if (this._listeners[event]) {
            this._listeners[event].forEach(cb => cb(data));
        }
        // Also dispatch a DOM event
        window.dispatchEvent(new CustomEvent(`omniencoder:${event}`, { detail: data }));
    },

    // Set input programmatically
    setInput(text) {
        const input = document.getElementById('input-text');
        if (input) {
            input.value = text;
            processText();
        }
    },

    // Set mode programmatically
    setMode(mode) {
        if (['encode', 'decode', 'auto', 'analyze'].includes(mode)) {
            setMode(mode);
        }
    },

    // Get current configuration
    getConfig() {
        return {
            mode: currentMode,
            activeEncoders: [...activeEncoders],
            chainSequence: [...chainSequence],
            theme: localStorage.getItem('omni_theme') || 'default'
        };
    }
};

// Legacy compatibility
window.omniResults = null;
window.omniComplete = false;

let processingTask = 0;
const SLOW_THRESHOLD = 80000; // 80KB triggers slow mode
const BATCH_SIZE = 4; // Process encoders in batches of 4 for smoother UI
const progressContainer = document.getElementById('progress-container');
const progressBar = document.getElementById('progress-bar');
const heavyWarning = document.getElementById('heavy-load-warning');

// Result cache to avoid re-processing identical input
let resultCache = { input: '', mode: '', results: {} };

const commonWords = ["the", "hi", "be", "to", "of", "and", "a", "in", "that", "have", "i", "it", "for", "not", "on", "with", "he", "as", "you", "do", "at", "this", "but", "his", "by", "from", "they", "we", "say", "her", "she", "or", "an", "will", "my", "one", "all", "would", "there", "their", "what", "so", "up", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
const natoRegex = /^((alpha|bravo|charlie|delta|echo|foxtrot|golf|hotel|india|juliett|kilo|lima|mike|november|oscar|papa|quebec|romeo|sierra|tango|uniform|victor|whiskey|x-ray|yankee|zulu|zero|one|two|three|four|five|six|seven|eight|nine|ze-ro|wun|too|tree|fow-er|fife|sev-en|ait|niner)\s*)+$/i;

/**
 * Updates the progress bar UI.
 * @param {number} percent - The completion percentage (0-100).
 */
function updateProgress(percent) {
    if (percent <= 0) progressContainer.classList.remove('hidden');
    progressBar.style.width = `${percent}%`;
    if (percent >= 100) setTimeout(() => progressContainer.classList.add('hidden'), 500);
}

/**
 * Safely parses a JSON string from localStorage.
 * @param {string} key - The localStorage key.
 * @param {*} fallback - The value to return if parsing fails or key doesn't exist.
 * @returns {*} The parsed object or the fallback.
 */
function safeJSONParse(key, fallback) {
    try {
        const item = localStorage.getItem(key);
        return item ? JSON.parse(item) : fallback;
    } catch (e) {
        console.warn(`Corrupted settings for ${key}, resetting to default.`);
        return fallback;
    }
}

let activeEncoders = safeJSONParse('omni_active_encoders', Object.keys(encoders));
// Ensure new encoders are added to the list if missing from localStorage
Object.keys(encoders).forEach(key => {
    if (!activeEncoders.includes(key)) activeEncoders.push(key);
});
let chainSequence = safeJSONParse('omni_chain_sequence', ['base64', 'reverse', 'rot13', 'hex', 'base64', 'octal', 'binary']);
let currentMode = localStorage.getItem('omni_mode') || 'encode';
let bestMatchEnabled = localStorage.getItem('omni_best_match') !== 'false'; // Default: enabled

/**
 * Sets the current application mode (encode or decode).
 * Updates the UI tabs and grid titles accordingly.
 * @param {string} mode - 'encode' or 'decode'.
 */
function setMode(mode) {
    currentMode = mode;
    localStorage.setItem('omni_mode', mode);

    // Update Tabs
    const tabEncode = document.getElementById('tab-encode');
    const tabDecode = document.getElementById('tab-decode');
    const tabAuto = document.getElementById('tab-auto');
    const tabAnalyze = document.getElementById('tab-analyze');

    const activeClass = "px-8 py-3 rounded-lg font-bold text-sm transition-all duration-200 bg-accent-600/80 backdrop-blur-md text-white shadow-lg shadow-accent-500/20 border border-accent-500/50";
    const inactiveClass = "px-8 py-3 rounded-lg font-bold text-sm transition-all duration-200 bg-white/5 backdrop-blur-md text-gray-400 hover:bg-white/10 hover:text-white border border-white/5 hover:border-white/10";

    const appSections = ['input-section', 'tool-chain', 'encoders-section'];
    const docSection = document.getElementById('doc-section');
    const autoSection = document.getElementById('auto-section');
    const analyzeSection = document.getElementById('analyze-section');

    docSection.classList.add('hidden');
    autoSection.classList.add('hidden');
    analyzeSection.classList.add('hidden');
    appSections.forEach(id => document.getElementById(id).classList.add('hidden'));
    bestMatchContainer.classList.add('hidden');
    bestMatchContainer.classList.remove('flex');

    tabEncode.className = inactiveClass;
    tabDecode.className = inactiveClass;
    tabAuto.className = inactiveClass;
    tabAnalyze.className = inactiveClass;

    if (mode === 'docs') {
        docSection.classList.remove('hidden');
    } else if (mode === 'auto') {
        tabAuto.className = activeClass;
        document.getElementById('input-section').classList.remove('hidden');
        autoSection.classList.remove('hidden');
        document.querySelector('label[for="input-text"]').innerText = "Input Data Stream";
        processText();
    } else if (mode === 'analyze') {
        tabAnalyze.className = activeClass;
        document.getElementById('input-section').classList.remove('hidden');
        analyzeSection.classList.remove('hidden');
        document.querySelector('label[for="input-text"]').innerText = "Input Data Stream";
        processAnalyze();
    } else {
        appSections.forEach(id => document.getElementById(id).classList.remove('hidden'));

        if (mode === 'encode') {
            tabEncode.className = activeClass;
            tabDecode.className = inactiveClass;
            document.querySelector('label[for="input-text"]').innerText = "Input Data Stream";
            document.getElementById('chain-title').innerText = "Multi-Layer Chain Encoder";
            document.getElementById('grid-title').innerText = "Standard Encoders";
        } else {
            tabDecode.className = activeClass;
            tabEncode.className = inactiveClass;
            document.querySelector('label[for="input-text"]').innerText = "Encoded Data Stream";
            document.getElementById('chain-title').innerText = "Multi-Layer Chain Decoder";
            document.getElementById('grid-title').innerText = "Standard Decoders";
        }
        initGrid();
        processText();
    }
}

/**
 * Initializes the grid of encoder/decoder cards based on active settings.
 */
function initGrid() {
    gridEl.innerHTML = '';
    activeEncoders.forEach(key => {
        // Skip encoders that don't have a corresponding decoder in Decode Mode (like Hashes)
        if (currentMode === 'decode' && !decoders[key]) return;

        const enc = encoders[key];
        const card = document.createElement('div');
        card.className = 'bg-gray-900/40 backdrop-blur-md rounded-xl border border-white/10 p-5 hover:border-white/20 hover:bg-gray-900/60 transition-all flex flex-col h-full group shadow-lg shadow-black/20 cursor-pointer';
        card.onclick = () => openQuickTool(key);
        card.innerHTML = `
            <div class="flex justify-between items-center mb-2 card-header">
                <div class="flex items-center gap-2 overflow-hidden">
                    <h3 class="font-bold text-gray-200 text-sm truncate select-none">${enc.name} ${currentMode === 'decode' ? '(Decode)' : ''}</h3>
                    <span id="score-${key}" class="hidden text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/10 text-gray-400"></span>
                </div>
                <div class="flex gap-0.5 ml-2 shrink-0 window-controls">
                    <button onclick="event.stopPropagation();" class="win-btn-min w-5 h-5 flex items-center justify-center rounded border border-white/20 bg-white/5 text-gray-400 cursor-default">
                        <div class="w-2 h-0.5 bg-current"></div>
                    </button>
                    <button onclick="event.stopPropagation();" class="win-btn-max w-5 h-5 flex items-center justify-center rounded border border-white/20 bg-white/5 text-gray-400 cursor-default">
                        <div class="w-2 h-2 border border-current"></div>
                    </button>
                    <button onclick="event.stopPropagation();" class="win-btn-close w-5 h-5 flex items-center justify-center rounded border border-white/20 bg-white/5 text-gray-400 cursor-default">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                    </button>
                </div>
            </div>
            <div id="card-body-${key}" class="flex-grow bg-black/40 rounded border border-white/5 p-3 mt-1 shadow-inner relative group/body transition-all">
                <button onclick="event.stopPropagation(); copyToClipboard('result-${key}')" class="absolute top-1 right-1 text-gray-500 hover:text-white p-1 opacity-0 group-hover/body:opacity-100 transition-opacity z-10 bg-black/50 rounded" title="Copy">
                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7v8a2 2 0 002 2h6M8 7V5a2 2 0 012-2h4.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V15a2 2 0 01-2 2h-2M8 7H6a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2v-2"></path></svg>
                </button>
                <div id="result-${key}" class="font-mono text-xs text-gray-400 break-all h-20 overflow-y-auto pr-1"></div>
            </div>
        `;
        gridEl.appendChild(card);
    });
    renderChainVisualizer();
}

/**
 * Updates the statistics (words, lines, bytes) for the given text.
 * @param {string} text - The input text.
 */
function updateStats(text) {
    const bytes = new Blob([text]).size;
    let lines = 0;
    if (text.length > 0) {
        lines = 1;
        for (let i = 0; i < text.length; i++) if (text[i] === '\n') lines++;
    }
    const words = text.length === 0 ? 0 : (text.length > 1000000 ? "N/A" : text.trim().split(/\s+/).length);

    statWords.innerText = `${words} words`;
    statLines.innerText = `${lines} lines`;
    statBytes.innerText = `${bytes} bytes`;
}

/**
 * Renders the visualization of the multi-layer chain sequence.
 */
function renderChainVisualizer() {
    chainVisualizerEl.innerHTML = '';
    chainStepCountEl.innerText = `${chainSequence.length} Steps`;

    const inputSpan = document.createElement('span');
    inputSpan.className = 'text-gray-400';
    inputSpan.innerText = 'Input';
    chainVisualizerEl.appendChild(inputSpan);

    const sequence = currentMode === 'encode' ? chainSequence : [...chainSequence].reverse();

    sequence.forEach((key, index) => {
        const arrow = document.createElement('span');
        arrow.className = 'mx-1 text-gray-700';
        arrow.innerText = '→';
        chainVisualizerEl.appendChild(arrow);

        const badge = document.createElement('span');
        badge.className = `chain-step-badge px-1.5 py-0.5 rounded bg-white/10 border border-white/5 text-gray-400 cursor-pointer hover:bg-red-900/30 hover:text-red-400 hover:border-red-500/30 transition-colors select-none ${index === sequence.length - 1 ? 'text-accent-500 font-bold' : ''}`;
        badge.innerText = encoders[key] ? encoders[key].name.substring(0, 4) : key;
        badge.title = "Click to remove step";

        const originalIndex = currentMode === 'encode' ? index : (chainSequence.length - 1 - index);
        badge.onclick = () => removeChainStep(originalIndex);

        chainVisualizerEl.appendChild(badge);
    });
}

/**
 * Calculates a confidence score for a given decoding result.
 * IMPROVED VERSION - better normalization and more accurate scoring
 * @param {string} key - The decoder key.
 * @param {string} text - The original input text.
 * @param {string} decoded - The decoded text.
 * @returns {number} The calculated score (0-200 raw, displayed as 0-100).
 */
function calculateHeuristicScore(key, text, decoded) {
    if (!decoded || decoded === "Error" || (typeof decoded === 'string' && decoded.startsWith("Invalid"))) return 0;
    if (decoded === text) return 0; // No change means not this encoding

    // Check for Image HTML result (data URI decode success)
    if (typeof decoded === 'string' && decoded.startsWith('<div class="flex flex-col items-center gap-2"><img')) return 250;

    let score = 0;
    const len = decoded.length;
    if (len === 0) return 0;

    // === Heuristic 1: Printable characters ratio (0-40 points) ===
    let printable = 0;
    let alphanumeric = 0;
    let spaces = 0;
    for (let i = 0; i < len; i++) {
        const code = decoded.charCodeAt(i);
        if ((code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9) {
            printable++;
            if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122) || (code >= 48 && code <= 57)) {
                alphanumeric++;
            }
            if (code === 32) spaces++;
        }
    }
    const printableRatio = printable / len;
    if (printableRatio < 0.7) return 0; // Too much garbage

    score += printableRatio * 25;

    // Bonus for high alphanumeric ratio (looks like real text)
    const alphaRatio = alphanumeric / len;
    score += alphaRatio * 15;

    // Bonus for having reasonable word-like spacing
    const spaceRatio = spaces / len;
    if (spaceRatio > 0.05 && spaceRatio < 0.25) score += 10;

    // === Heuristic 2: Input format matching (0-70 points) ===
    const t = text.trim();
    const tLen = t.length;
    let formatMatch = false;

    // Check simpler/more specific patterns FIRST, then fallback to generic ones
    // This prevents Base58 from matching binary/octal/hex inputs

    const isBinaryLike = /^[01\s]+$/.test(t);
    const isOctalLike = /^[0-7\s]+$/.test(t);
    const isHexLike = /^(0x)?[0-9A-Fa-f\s]+$/.test(t);
    const isNumbersOnly = /^[\d\-\s]+$/.test(t);

    if (key === 'binary' && isBinaryLike && t.replace(/\s/g, '').length % 8 === 0 && tLen >= 8) {
        score += 70; formatMatch = true;
    } else if (key === 'octal' && isOctalLike && !isBinaryLike && tLen >= 3) {
        // Octal but not binary
        score += 55; formatMatch = true;
    } else if (key === 'hex' && isHexLike && !isOctalLike && t.replace(/[^0-9A-Fa-f]/g, '').length % 2 === 0 && tLen >= 2) {
        score += 60; formatMatch = true;
    } else if (key === 'base64' && /^[A-Za-z0-9+/]+={0,2}$/.test(t) && t.length % 4 === 0 && tLen >= 4) {
        score += 60; formatMatch = true;
    } else if (key === 'base58' && /^[1-9A-HJ-NP-Za-km-z]+$/.test(t) && !natoRegex.test(t) &&
        !isBinaryLike && !isOctalLike && !isNumbersOnly && tLen >= 8) {
        // Base58: Must NOT match simpler patterns and must be at least 8 chars
        score += 45; formatMatch = true;
    } else if (key === 'morse' && /^[\.\-\/\s]+$/.test(t) && tLen >= 3) {
        score += 75; formatMatch = true;
    } else if (key === 'htmlEnt' && /&[#a-zA-Z0-9]+;/.test(t)) {
        score += 70; formatMatch = true;
    } else if (key === 'url' && /%[0-9A-F]{2}/i.test(t)) {
        score += 65; formatMatch = true;
    } else if (key === 'unicode' && /\\u[0-9A-Fa-f]{4}/.test(t)) {
        score += 65; formatMatch = true;
    } else if (key === 'tap' && /^([1-5]{2}\s*)+$/.test(t) && tLen >= 4) {
        score += 60; formatMatch = true;
    } else if (key === 'jwt' && t.split('.').length === 3 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(t)) {
        score += 80; formatMatch = true;
    } else if (key === 'bacon' && /^[ab\s]+$/i.test(t) && t.replace(/\s/g, '').length % 5 === 0 && tLen >= 5) {
        score += 65; formatMatch = true;
    } else if (key === 'quotedPrintable' && /=[0-9A-F]{2}/.test(t)) {
        score += 60; formatMatch = true;
    } else if (key === 'dert' && /^[Dert\s]+$/.test(t) && t.replace(/\s/g, '').length % 4 === 0 && tLen >= 4) {
        score += 65; formatMatch = true;
    } else if (key === 'nato' && natoRegex.test(t)) {
        score += 70; formatMatch = true;
    } else if (key === 'caesar' && /^[a-zA-Z\s]+$/.test(t) && tLen >= 3) {
        // Caesar only for 3+ character inputs
        score += 15; // Very low - it's highly ambiguous
    } else if (key === 'a1z26' && isNumbersOnly && tLen >= 2) {
        score += 60; formatMatch = true;
    }

    // === Heuristic 3: Dictionary/Common words check (0-50 points) ===
    const lower = decoded.toLowerCase();
    let wordHits = 0;
    const words = lower.split(/\s+/);

    commonWords.forEach(w => {
        // More precise word matching
        if (words.includes(w) || lower.includes(' ' + w + ' ') ||
            lower.startsWith(w + ' ') || lower.endsWith(' ' + w)) {
            wordHits++;
        }
    });

    // Scale by output length (longer outputs with more words = more reliable)
    const wordBonus = Math.min(wordHits * 8, 50);
    score += wordBonus;

    // === Heuristic 4: Length ratio check (0-20 points) ===
    // Good decodings typically expand or contract text in predictable ways
    const lengthRatio = len / text.length;
    if (key === 'binary' && lengthRatio > 0.1 && lengthRatio < 0.2) score += 20;
    else if (key === 'hex' && lengthRatio > 0.4 && lengthRatio < 0.6) score += 15;
    else if (key === 'base64' && lengthRatio > 0.7 && lengthRatio < 0.8) score += 15;
    else if (lengthRatio > 0.3 && lengthRatio < 2.0) score += 10;

    // === Bonus: If format matches AND has dictionary words, high confidence ===
    if (formatMatch && wordHits >= 2) score += 25;

    return score;
}

/**
 * Attempts to find the best matching decoder for the given text based on heuristics.
 * @param {string} text - The encoded text.
 * @returns {object|null} The best match object { key, score, decoded }, or null.
 */
async function findBestMatch(text) {
    if (!text || text.trim().length === 0) return null;

    let best = null;
    let maxScore = 0;

    for (const key of Object.keys(decoders)) {
        // Skip transformations that don't imply a specific format
        if (key === 'reverse' || key === 'rot13' || key === 'atbash' || key === 'leet') continue;

        try {
            const decoded = await decoders[key](text);
            const score = calculateHeuristicScore(key, text, decoded);
            if (score <= 0) continue;

            if (score > maxScore) {
                maxScore = score;
                best = { key, score, decoded };
            }
        } catch (e) { }
    }

    return maxScore > 60 ? best : null;
}

/**
 * Runs the recursive auto-detection logic.
 */
async function processAutoMode() {
    const text = inputEl.value;
    const stepsContainer = document.getElementById('auto-steps');
    const resultEl = document.getElementById('auto-result');

    window.omniComplete = false;
    window.omniResults = { mode: 'auto', steps: [], final: null };

    stepsContainer.innerHTML = '';
    resultEl.innerText = '';

    if (!text) {
        resultEl.innerText = 'Waiting for input...';
        return;
    }

    let current = text;
    let depth = 0;
    const maxDepth = 10;

    while (depth < maxDepth) {
        const match = await findBestMatch(current);

        if (!match) break;

        // Render Step
        const div = document.createElement('div');
        div.className = 'flex items-center justify-between bg-white/5 p-3 rounded border border-white/10';

        let badgeColor = 'bg-red-500/20 text-red-400 border-red-500/20';
        if (match.score >= 120) badgeColor = 'bg-emerald-500/20 text-emerald-400 border-emerald-500/20';
        else if (match.score > 80) badgeColor = 'bg-orange-500/20 text-orange-400 border-orange-500/20';

        const displayScore = Math.min(Math.round(match.score), 100);

        div.innerHTML = `
            <div class="flex items-center gap-3">
                <span class="text-gray-400 font-mono text-xs">${depth + 1}.</span>
                <span class="font-bold text-gray-200">${encoders[match.key].name}</span>
            </div>
            <span class="text-xs font-mono px-2 py-1 rounded border ${badgeColor}">
                ${displayScore}% Conf.
            </span>
        `;
        stepsContainer.appendChild(div);

        window.omniResults.steps.push({
            tool: encoders[match.key].name,
            confidence: match.score,
            output: match.decoded
        });

        current = match.decoded;
        depth++;
    }

    if (depth === 0) {
        stepsContainer.innerHTML = '<div class="text-gray-500 italic text-sm">No encoding pattern detected.</div>';
    }

    // Render HTML if the result is an image preview, otherwise text
    if (typeof current === 'string' && current.startsWith('<div')) resultEl.innerHTML = current;
    else resultEl.innerText = current;

    window.omniResults.final = current;
    window.omniComplete = true;
    console.log("OmniEncoder Result:", window.omniResults);
}

/**
 * Calculates and displays Entropy and Frequency analysis.
 */
function processAnalyze() {
    const text = inputEl.value;
    const entropyEl = document.getElementById('entropy-value');
    const entropyDesc = document.getElementById('entropy-desc');
    const freqChart = document.getElementById('freq-chart');
    const typeEl = document.getElementById('analyze-type');

    window.omniComplete = false;
    window.omniResults = { mode: 'analyze', entropy: 0, type: 'Unknown', frequency: {} };

    if (!text) {
        entropyEl.innerText = "0.00";
        freqChart.innerHTML = '<div class="text-gray-500 italic">Waiting for input...</div>';
        renderHexDump('');
        return;
    }

    // Entropy Calculation
    const len = text.length;
    const freqs = {};
    for (let char of text) freqs[char] = (freqs[char] || 0) + 1;

    let entropy = 0;
    Object.values(freqs).forEach(count => {
        const p = count / len;
        entropy -= p * Math.log2(p);
    });

    entropyEl.innerText = entropy.toFixed(2);
    if (entropy > 7.5) entropyDesc.innerText = "High Randomness (Encrypted/Compressed)";
    else if (entropy > 5) entropyDesc.innerText = "Moderate Randomness (Code/Base64)";
    else entropyDesc.innerText = "Low Randomness (Natural Text)";

    // Type Detection
    let type = "Unknown / Raw Text";
    const t = text.trim();
    if (t.startsWith('{') && t.endsWith('}')) type = "JSON (Potential)";
    else if (t.startsWith('<') && t.endsWith('>')) type = "XML / HTML (Potential)";
    else if (/^[A-Za-z0-9+/]+={0,2}$/.test(t) && t.length % 4 === 0 && !t.includes(' ')) type = "Base64 (Potential)";
    else if (natoRegex.test(t)) type = "NATO Phonetic (Potential)";
    else if (/^[1-9A-HJ-NP-Za-km-z]+$/.test(t)) type = "Base58 (Potential)";
    else if (/^([0-9A-Fa-f]{2}\s*)+$/.test(t)) type = "Hex String (Potential)";
    else if (/^[Dert\s]+$/.test(t)) type = "Dert Cipher (Potential)";
    typeEl.innerText = `Type: ${type}`;

    window.omniResults.entropy = entropy;
    window.omniResults.type = type;
    window.omniResults.frequency = freqs;

    // Frequency Chart
    const sorted = Object.entries(freqs).sort((a, b) => b[1] - a[1]).slice(0, 10);
    freqChart.innerHTML = '';
    const maxVal = sorted[0][1];

    sorted.forEach(([char, count]) => {
        const percent = (count / maxVal) * 100;
        const label = char === ' ' ? 'SPACE' : (char === '\n' ? '\\n' : char);
        freqChart.innerHTML += `<div class="flex items-center gap-2 text-xs"><div class="w-8 text-right font-mono text-gray-400">${label}</div><div class="flex-grow bg-white/5 rounded-full h-2 overflow-hidden"><div class="bg-accent-500 h-full" style="width: ${percent}%"></div></div><div class="w-8 text-gray-500">${count}</div></div>`;
    });

    renderHexDump(text);
    window.omniComplete = true;
    console.log("OmniEncoder Result:", window.omniResults);
}

/**
 * Renders a Hex Dump of the input text.
 * @param {string} text 
 */
function renderHexDump(text) {
    const hexDumpEl = document.getElementById('hex-dump');
    if (!text) {
        hexDumpEl.innerText = '';
        return;
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    let output = '';
    const len = data.length;
    const limit = Math.min(len, 4096); // Limit for performance

    for (let i = 0; i < limit; i += 16) {
        const offset = i.toString(16).padStart(8, '0');
        const chunk = data.slice(i, i + 16);

        let hex = '';
        let ascii = '';

        for (let j = 0; j < 16; j++) {
            if (j < chunk.length) {
                const byte = chunk[j];
                hex += byte.toString(16).padStart(2, '0') + ' ';
                ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
            } else {
                hex += '   ';
            }
            if (j === 7) hex += ' ';
        }
        output += `${offset}  ${hex} |${ascii}|\n`;
    }

    if (len > limit) output += `... (${len - limit} bytes truncated)`;
    hexDumpEl.innerText = output;
}

/**
 * Main processing function - OPTIMIZED VERSION
 * Uses caching, batch processing, and parallel execution for better performance.
 */
async function processText() {
    const text = inputEl.value;
    const taskId = Date.now();
    processingTask = taskId;

    window.omniComplete = false;
    window.omniResults = { mode: currentMode, input: text, outputs: {}, chain: null };

    updateStats(text);

    // Check cache - skip processing if input unchanged
    const cacheKey = `${text}_${currentMode}`;
    const useCache = resultCache.key === cacheKey && Object.keys(resultCache.results).length > 0;

    const isHeavy = text.length > SLOW_THRESHOLD;
    if (isHeavy) {
        heavyWarning.classList.remove('hidden');
        updateProgress(0);
    } else {
        heavyWarning.classList.add('hidden');
        progressContainer.classList.add('hidden');
    }

    if (currentMode === 'auto') {
        await processAutoMode();
        if (isHeavy) updateProgress(100);
        return;
    }

    if (currentMode === 'analyze') {
        processAnalyze();
        if (isHeavy) updateProgress(100);
        return;
    }

    // Handle Best Match (Decode Mode Only) - defer to avoid blocking
    if (currentMode === 'decode' && text.length > 0 && bestMatchEnabled) {
        // Use requestIdleCallback if available, otherwise setTimeout
        const deferBestMatch = () => {
            if (processingTask !== taskId) return;
            findBestMatch(text).then(best => {
                if (processingTask !== taskId) return;
                if (best && best.score > 110) {
                    bestMatchContainer.classList.remove('hidden');
                    bestMatchContainer.classList.add('flex');
                    bestMatchName.innerHTML = `${encoders[best.key].name} <span class="text-xs bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded ml-2 border border-emerald-500/20">${Math.min(Math.round(best.score), 100)}% Conf.</span>`;
                    bestMatchResult.innerText = best.decoded;
                } else {
                    bestMatchContainer.classList.add('hidden');
                    bestMatchContainer.classList.remove('flex');
                }
            });
        };
        if ('requestIdleCallback' in window) {
            requestIdleCallback(deferBestMatch, { timeout: 500 });
        } else {
            setTimeout(deferBestMatch, 50);
        }
    } else {
        bestMatchContainer.classList.add('hidden');
        bestMatchContainer.classList.remove('flex');
    }

    const totalSteps = activeEncoders.length + chainSequence.length;
    let completedSteps = 0;

    // Process chain FIRST (it's the primary output users care about)
    if (text.length > 0) {
        try {
            let current = text;
            const sequence = currentMode === 'encode' ? chainSequence : [...chainSequence].reverse();

            const badges = document.querySelectorAll('.chain-step-badge');
            badges.forEach(b => b.classList.remove('bg-red-500/20', 'text-red-400', 'border-red-500/50', 'animate-pulse'));

            let stepIndex = 0;
            for (const key of sequence) {
                if (processingTask !== taskId) return;

                if (typeof current === 'string' && current.length > 20000000) {
                    chainResultEl.innerText = "Chain output exceeded 20MB limit. Processing aborted.";
                    break;
                }

                let next = null;
                try {
                    if (currentMode === 'encode') {
                        next = encoders[key] ? await encoders[key].fn(current) : current;
                    } else {
                        next = decoders[key] ? await decoders[key](current) : current;
                    }
                } catch (e) { next = "Error"; }

                if (next && (typeof next === 'string') && (next.startsWith("Invalid") || next === "Error")) {
                    if (badges[stepIndex]) {
                        badges[stepIndex].classList.remove('text-gray-400', 'text-accent-500');
                        badges[stepIndex].classList.add('bg-red-500/20', 'text-red-400', 'border-red-500/50', 'animate-pulse');
                    }
                    chainResultEl.innerHTML = `<span class="text-red-400 font-bold">Chain Broken at step "${encoders[key]?.name || key}":</span> <span class="text-gray-400">${next}</span>`;
                    current = null;
                    break;
                }
                current = next;
                stepIndex++;
            }

            if (current !== null) {
                if (typeof current === 'string' && current.startsWith('<div')) chainResultEl.innerHTML = current;
                else chainResultEl.innerText = current;
                window.omniResults.chain = current;
            }
        } catch (e) {
            chainResultEl.innerText = "Error in chain calculation.";
        }
    } else {
        chainResultEl.innerHTML = '<span class="text-gray-600 italic">Start typing to generate chain...</span>';
    }

    // Process encoders in BATCHES using requestAnimationFrame for smooth UI
    const processBatch = async (startIdx) => {
        if (processingTask !== taskId) return;

        const endIdx = Math.min(startIdx + BATCH_SIZE, activeEncoders.length);
        const batch = activeEncoders.slice(startIdx, endIdx);

        // Process batch in parallel
        await Promise.all(batch.map(async (key) => {
            if (processingTask !== taskId) return;

            let outputVal = null;
            const el = document.getElementById(`result-${key}`);
            const scoreEl = document.getElementById(`score-${key}`);

            if (!el) return;

            if (text.length === 0) {
                el.innerText = 'Waiting for input...';
                el.className = 'font-mono text-xs text-gray-600 italic h-20 overflow-y-auto pr-1';
                if (scoreEl) scoreEl.classList.add('hidden');
                return;
            }

            // Use cache if available
            if (useCache && resultCache.results[key] !== undefined) {
                outputVal = resultCache.results[key];
            } else {
                try {
                    if (currentMode === 'encode') {
                        outputVal = await encoders[key].fn(text);
                    } else {
                        outputVal = decoders[key] ? await decoders[key](text) : "No decoder";
                    }
                } catch (e) {
                    outputVal = "Error";
                }
            }

            if (processingTask !== taskId) return;

            // Update DOM
            if (typeof outputVal === 'string' && outputVal.startsWith('<div')) {
                el.innerHTML = outputVal;
            } else {
                el.innerText = outputVal;
            }
            el.className = 'font-mono text-xs text-gray-300 break-all h-20 overflow-y-auto pr-1';

            // Handle score display (decode mode only)
            if (scoreEl) {
                if (currentMode === 'decode' && decoders[key]) {
                    const score = calculateHeuristicScore(key, text, outputVal);
                    const displayedScore = Math.min(Math.round(score), 100);
                    if (score > 0) {
                        scoreEl.innerText = `${displayedScore}%`;
                        // Color based on displayed percentage, not raw score
                        scoreEl.className = 'text-[10px] font-mono px-1.5 py-0.5 rounded ' +
                            (displayedScore >= 90 ? 'bg-emerald-500/20 text-emerald-400' :
                                displayedScore >= 60 ? 'bg-orange-500/20 text-orange-400' : 'bg-white/10 text-gray-400');
                        scoreEl.style.display = 'inline-block';
                    } else {
                        scoreEl.classList.add('hidden');
                    }
                } else {
                    scoreEl.classList.add('hidden');
                }
            }

            // Store in cache
            resultCache.results[key] = outputVal;
            if (window.omniResults?.outputs) {
                window.omniResults.outputs[key] = outputVal;
            }
        }));

        completedSteps += batch.length;
        if (isHeavy) updateProgress((completedSteps / totalSteps) * 100);

        // Schedule next batch
        if (endIdx < activeEncoders.length) {
            requestAnimationFrame(() => processBatch(endIdx));
        } else {
            // All done
            resultCache.key = cacheKey;
            window.omniComplete = true;
            if (isHeavy) updateProgress(100);
            // Emit complete event through API
            window.OmniEncoder._emit('complete', window.omniResults);
        }
    };

    // Start batch processing
    if (activeEncoders.length > 0) {
        requestAnimationFrame(() => processBatch(0));
    } else {
        window.omniComplete = true;
        if (isHeavy) updateProgress(100);
    }
}

/**
 * Copies text from a specific element to the clipboard.
 * @param {string} elementId - The ID of the element containing text to copy.
 */
function copyToClipboard(elementId) {
    const el = document.getElementById(elementId);
    const text = el.innerText;
    copyText(text);
}

/**
 * Generates a shareable URL with current state (text, mode, encoders) and copies it.
 */
function copyShareLink() {
    const url = new URL(window.location.href);
    url.searchParams.set('text', inputEl.value);
    url.searchParams.set('mode', currentMode);
    url.searchParams.set('encoders', activeEncoders.join(','));
    copyText(url.toString());
}

/**
 * Helper to copy text to clipboard using Clipboard API or fallback.
 * @param {string} text - The text to copy.
 */
async function copyText(text) {
    if (!text || text.includes('Waiting for input')) return;

    // Try Modern Clipboard API first
    if (navigator.clipboard && window.isSecureContext) {
        try {
            await navigator.clipboard.writeText(text);
            showToast();
            return;
        } catch (err) { console.error('Clipboard API failed, falling back', err); }
    }

    // Fallback for older browsers or non-secure contexts
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'absolute';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();

    try {
        document.execCommand('copy');
        showToast();
    } catch (err) { }
    document.body.removeChild(textarea);
}

/**
 * Displays a temporary toast notification.
 */
function showToast() {
    const toast = document.getElementById('toast');
    toast.classList.remove('translate-y-24', 'opacity-0');
    setTimeout(() => {
        toast.classList.add('translate-y-24', 'opacity-0');
    }, 2000);
}

/**
 * Creates a debounced version of a function.
 * @param {Function} func - The function to debounce.
 * @param {number} wait - The delay in milliseconds.
 * @returns {Function} The debounced function.
 */
function debounce(func, wait) {
    let timeout;
    return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

/**
 * Toggles the visibility of the settings modal.
 */
function toggleSettings() {
    const modal = document.getElementById('settings-modal');
    const isHidden = modal.classList.contains('hidden');
    if (isHidden) {
        modal.classList.remove('hidden');
        renderSettings();
    } else {
        modal.classList.add('hidden');
    }
}

/**
 * Applies the selected visual theme to the application.
 * @param {string} theme - The theme identifier ('default' or 'winxp').
 */
function applyTheme(theme) {
    localStorage.setItem('omni_theme', theme);
    let style = document.getElementById('omni-theme-style');
    if (!style) {
        style = document.createElement('style');
        style.id = 'omni-theme-style';
        document.head.appendChild(style);
    }

    if (theme === 'winxp') {
        style.innerHTML = `
            body { 
                background: #245edb url('theme-1.png') no-repeat center center fixed !important; 
                background-size: cover !important; 
                font-family: 'Tahoma', 'Verdana', sans-serif !important; 
                font-size: 11px !important;
            }
            
            /* Main Windows / Cards / Modals */
            .bg-gray-900, .bg-gray-800, .backdrop-blur-md, .bg-gray-900\\/40, .bg-gray-900\\/60, .bg-gray-900\\/30 { 
                background-color: #ECE9D8 !important; 
                color: black !important; 
                backdrop-filter: none !important; 
                border: 3px solid #0054E3 !important; 
                border-radius: 8px 8px 0 0 !important; 
                box-shadow: 4px 4px 12px rgba(0,0,0,0.4) !important; 
            }
            
            /* Title Bars */
            .bg-gray-900\\/60 > div:first-child, .bg-gray-900\\/40 > div:first-child, .bg-gray-800 > div:first-child, .bg-gray-900 > div:first-child { 
                background: linear-gradient(to bottom, #0058EE 0%, #3593FF 4%, #288EFF 18%, #127dff 20%, #0369fc 39%, #0262ee 40%, #0057e5 100%) !important; 
                border-radius: 5px 5px 0 0 !important; 
                border-bottom: 1px solid #003c74 !important; 
                padding: 8px 12px !important;
                margin: -3px -3px 10px -3px !important;
            }

            .text-gray-200, .text-gray-300, .text-gray-400, .text-gray-500, .text-gray-600, .text-gray-700 { color: #000 !important; }
            .text-accent-500 { color: #d53c00 !important; }
            .border-white\\/10, .border-white\\/20, .border-white\\/5 { border-color: #0054e3 !important; }
            
            /* Inputs & Content Areas */
            .bg-white\\/5, .bg-white\\/10, .bg-black\\/40 { background-color: #fff !important; border: 2px solid #7f9db9 !important; color: black !important; border-radius: 0 !important; }
            input, textarea, select { background-color: #fff !important; color: #000 !important; border: 2px solid #7f9db9 !important; border-radius: 0 !important; font-family: 'Tahoma', sans-serif !important; }
            
            /* Buttons */
            button { background: linear-gradient(180deg, #fcfdfe 0%, #f4f3ee 100%) !important; border: 1px solid #003c74 !important; color: black !important; border-radius: 3px !important; font-family: 'Tahoma', sans-serif !important; }
            button:hover { background: linear-gradient(180deg, #f4f3ee 0%, #fcfdfe 100%) !important; box-shadow: inset 0 0 2px 2px #f8b334 !important; }
            
            /* Active Tabs / Primary Buttons */
            .bg-accent-600\\/80 { background: linear-gradient(180deg, #3e8fff 0%, #245edb 100%) !important; border: 1px solid #003c74 !important; color: white !important; font-weight: bold !important; text-shadow: 1px 1px 0 rgba(0,0,0,0.3); border-radius: 3px !important; }
            
            /* Text Overrides in Title Bars */
            .bg-gray-900\\/60 > div:first-child h2, .bg-gray-900\\/40 > div:first-child h3, .bg-gray-900 > div:first-child h3, .bg-gray-800 > div:first-child h2 { color: white !important; font-weight: bold; text-shadow: 1px 1px 1px rgba(0,0,0,0.5); font-family: 'Tahoma', sans-serif !important; }
            .bg-gray-900\\/40 > div:first-child p { color: #cce5ff !important; }
            .bg-gray-900\\/40 > div:first-child button, .bg-gray-900\\/60 > div:first-child button { background: none !important; border: none !important; color: white !important; box-shadow: none !important; }
            
            /* Window Controls Specifics */
            .window-controls { gap: 2px !important; margin-right: -4px !important; margin-top: -4px !important; }
            .window-controls button {
                width: 18px !important; height: 18px !important;
                border-radius: 3px !important;
                border: 1px solid white !important;
                box-shadow: 1px 1px 2px rgba(0,0,0,0.3) !important;
                padding: 0 !important;
                opacity: 1 !important;
            }
            
            /* Minimize & Maximize */
            .win-btn-min, .win-btn-max { background: linear-gradient(180deg, #fff 0%, #ece9d8 100%) !important; color: black !important; }
            .win-btn-min div { background-color: black !important; width: 6px !important; height: 2px !important; margin-top: 6px !important; }
            .win-btn-max div { border-color: black !important; border-width: 1px !important; width: 10px !important; height: 9px !important; border-top-width: 2px !important; }

            /* Close Button */
            .win-btn-close {
                background: linear-gradient(180deg, #e05252 0%, #b00000 100%) !important;
                border: 1px solid #fff !important;
                box-shadow: 1px 1px 2px rgba(0,0,0,0.3) !important;
                width: 20px !important; height: 20px !important;
                display: flex !important; align-items: center !important; justify-content: center !important;
            }
            .win-btn-close svg { color: white !important; }
        `;
    } else {
        style.innerHTML = '';
    }
}

/**
 * Renders the settings modal content (chain editor, encoder toggles).
 */
function renderSettings() {
    // Chain Editor
    const chainList = document.getElementById('chain-editor-list');
    chainList.innerHTML = '';

    const chainToolbar = document.createElement('div');
    chainToolbar.className = 'flex gap-2 mb-2 pb-2 border-b border-white/10 justify-end';

    const btnChainAddAll = document.createElement('button');
    btnChainAddAll.innerText = 'Add All';
    btnChainAddAll.className = 'text-xs bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 px-2 py-1 rounded transition-colors';
    btnChainAddAll.onclick = () => {
        if (confirm("Adding all encoders creates a very long chain that may produce massive output. Are you sure?")) {
            chainSequence = Object.keys(encoders).filter(k => encoders[k].reversible !== false);
            renderSettings();
            saveSettings();
        }
    };

    const btnChainClear = document.createElement('button');
    btnChainClear.innerText = 'Clear';
    btnChainClear.className = 'text-xs bg-white/5 hover:bg-red-900/30 text-gray-300 hover:text-red-400 border border-white/10 px-2 py-1 rounded transition-colors';
    btnChainClear.onclick = () => { if (confirm('Clear chain?')) { chainSequence = []; renderSettings(); saveSettings(); } };

    chainToolbar.appendChild(btnChainAddAll);
    chainToolbar.appendChild(btnChainClear);
    chainList.appendChild(chainToolbar);

    chainSequence.forEach((step, index) => {
        const div = document.createElement('div');
        div.className = 'flex justify-between items-center bg-white/5 p-2 rounded border border-white/10';
        div.innerHTML = `
            <span class="text-sm text-gray-300 font-mono"><span class="text-gray-600 mr-2">${index + 1}.</span>${encoders[step]?.name || step}</span>
            <button onclick="removeChainStep(${index})" class="text-red-500 hover:text-red-400 p-1">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>
        `;
        chainList.appendChild(div);
    });

    // Chain Add Select
    const addSelect = document.getElementById('chain-add-select');
    addSelect.innerHTML = '';
    Object.keys(encoders).forEach(key => {
        const opt = document.createElement('option');
        opt.value = key;
        opt.innerText = encoders[key].name;
        addSelect.appendChild(opt);
    });

    // Encoders Grid
    const grid = document.getElementById('settings-encoders-grid');
    grid.innerHTML = '';

    const toolbar = document.createElement('div');
    toolbar.className = 'col-span-full flex gap-2 mb-2 pb-2 border-b border-white/10';
    toolbar.style.gridColumn = '1 / -1';

    const allSelected = activeEncoders.length === Object.keys(encoders).length;
    const btnToggle = document.createElement('button');
    btnToggle.innerText = allSelected ? 'Deselect All' : 'Select All';
    btnToggle.className = 'text-xs bg-white/5 hover:bg-white/10 text-gray-400 border border-white/10 px-2 py-1 rounded transition-colors';
    btnToggle.onclick = () => toggleAllEncoders(!allSelected);

    toolbar.appendChild(btnToggle);

    const btnReset = document.createElement('button');
    btnReset.innerText = 'Factory Reset';
    btnReset.className = 'text-xs bg-white/5 hover:bg-red-900/30 text-gray-400 hover:text-red-400 border border-white/10 px-2 py-1 rounded transition-colors ml-auto';
    btnReset.onclick = resetSettings;
    toolbar.appendChild(btnReset);

    grid.appendChild(toolbar);

    Object.keys(encoders).forEach(key => {
        const isChecked = activeEncoders.includes(key);
        const label = document.createElement('label');
        label.className = 'flex items-center gap-2 p-2 rounded border border-white/10 bg-white/5 cursor-pointer hover:bg-white/10';
        label.innerHTML = `
            <input type="checkbox" value="${key}" class="w-3.5 h-3.5 rounded border-white/20 bg-black/40 text-accent-500 focus:ring-accent-500/50" ${isChecked ? 'checked' : ''} onchange="saveSettings()">
            <span class="text-xs text-gray-300">${encoders[key].name}</span>
        `;
        grid.appendChild(label);
    });
}

/**
 * Adds a new step to the chain sequence based on the dropdown selection.
 */
function addChainStep() {
    const select = document.getElementById('chain-add-select');
    chainSequence.push(select.value);
    renderSettings();
    saveSettings();
}

/**
 * Removes a step from the chain sequence.
 * @param {number} index - The index of the step to remove.
 */
function removeChainStep(index) {
    chainSequence.splice(index, 1);
    renderSettings();
    saveSettings();
}

/**
 * Selects or deselects all standard encoders.
 * @param {boolean} select - True to select all, false to deselect all.
 */
function toggleAllEncoders(select) {
    activeEncoders = select ? Object.keys(encoders) : [];
    renderSettings();
    saveSettings();
}

/**
 * Resets all application settings to their default values.
 */
function resetSettings() {
    if (confirm('Are you sure you want to reset all settings to default?')) {
        Object.keys(localStorage).forEach(key => {
            if (key.startsWith('omni_')) localStorage.removeItem(key);
        });
        activeEncoders = Object.keys(encoders);
        chainSequence = ['base64', 'reverse', 'rot13', 'hex', 'base64', 'octal', 'binary'];
        bestMatchEnabled = true;

        const defaultTheme = 'default';
        applyTheme(defaultTheme);
        const themeSelect = document.getElementById('theme-select');
        if (themeSelect) themeSelect.value = defaultTheme;

        const bestMatchToggle = document.getElementById('best-match-toggle');
        if (bestMatchToggle) bestMatchToggle.checked = true;

        setMode('encode');
        renderSettings();
        saveSettings();
    }
}

/**
 * Toggles the Best Match feature on/off.
 */
function toggleBestMatch() {
    const toggle = document.getElementById('best-match-toggle');
    bestMatchEnabled = toggle ? toggle.checked : !bestMatchEnabled;
    localStorage.setItem('omni_best_match', bestMatchEnabled);

    // Hide Best Match container if disabled
    if (!bestMatchEnabled) {
        bestMatchContainer.classList.add('hidden');
        bestMatchContainer.classList.remove('flex');
    } else if (currentMode === 'decode') {
        // Re-run detection if we're in decode mode
        processText();
    }
}

/**
 * Saves the current settings to localStorage and refreshes the UI.
 */
function saveSettings() {
    // Save Encoders
    const checkboxes = document.querySelectorAll('#settings-encoders-grid input[type="checkbox"]:checked');
    activeEncoders = Array.from(checkboxes).map(cb => cb.value);
    localStorage.setItem('omni_active_encoders', JSON.stringify(activeEncoders));

    // Save Chain
    localStorage.setItem('omni_chain_sequence', JSON.stringify(chainSequence));

    initGrid();
    processText();
}

const dropZone = inputEl.parentElement;

['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => { e.preventDefault(); e.stopPropagation(); }, false);
});

['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, () => {
        dropZone.classList.add('border-accent-500', 'bg-gray-800');
        dropZone.classList.remove('border-gray-800', 'bg-gray-900/50');
    }, false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, () => {
        dropZone.classList.remove('border-accent-500', 'bg-gray-800');
        dropZone.classList.add('border-gray-800', 'bg-gray-900/50');
    }, false);
});

dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
        const file = files[0];
        const reader = new FileReader();

        // Feature 1: Image Support
        if (file.type.startsWith('image/')) {
            reader.onload = (e) => { inputEl.value = e.target.result.split(',')[1]; processText(); }; // Strip data:image... prefix
            reader.readAsDataURL(file);
            return;
        }

        reader.onload = (e) => { inputEl.value = e.target.result; processText(); };
        reader.readAsText(file);
    }
}, false);

let currentQuickToolKey = null;

/**
 * Opens the quick tool modal for a specific encoder/decoder.
 * @param {string} key - The key of the encoder/decoder.
 */
function openQuickTool(key) {
    currentQuickToolKey = key;
    const modal = document.getElementById('quick-tool-modal');
    const title = document.getElementById('quick-tool-title');
    const input = document.getElementById('quick-tool-input');
    const verifySection = document.getElementById('quick-tool-verify-section');
    const verifyInput = document.getElementById('quick-tool-verify-input');
    const passwordSection = document.getElementById('quick-tool-password-section');
    const passwordInput = document.getElementById('quick-tool-password');
    const inputLabel = document.querySelector('label[for="quick-tool-input"]');
    const diffBtn = document.getElementById('btn-diff-toggle');

    title.innerText = `${encoders[key].name} ${currentMode === 'decode' ? '(Decode)' : '(Encode)'}`;
    input.value = inputEl.value; // Pre-fill with main input

    if (currentMode === 'decode' && ['sha1', 'sha256', 'sha512', 'crc32', 'adler32'].includes(key)) {
        verifySection.classList.remove('hidden');
        verifyInput.value = '';
        verifyInput.oninput = updateQuickTool;
        if (inputLabel) inputLabel.innerText = "Target Hash";
        title.innerText = `${encoders[key].name} (Verify)`;
    } else {
        verifySection.classList.add('hidden');
        if (inputLabel) inputLabel.innerText = "Input";
    }

    if (key === 'aes' || key === 'vigenere' || key === 'jwt') {
        passwordSection.classList.remove('hidden');
        passwordInput.value = '';
    } else {
        passwordSection.classList.add('hidden');
    }

    diffBtn.classList.remove('text-accent-500'); // Reset diff toggle
    diffBtn.classList.add('text-gray-500');
    modal.classList.remove('hidden');
    updateQuickTool();

    input.oninput = updateQuickTool;
    passwordInput.oninput = updateQuickTool;
}

/**
 * Closes the quick tool modal.
 */
function closeQuickTool() {
    document.getElementById('quick-tool-modal').classList.add('hidden');
    currentQuickToolKey = null;
}

/**
 * Toggles the Diff View in the Quick Tool.
 */
async function toggleDiffView() {
    const btn = document.getElementById('btn-diff-toggle');
    const outputEl = document.getElementById('quick-tool-output');
    const input = document.getElementById('quick-tool-input').value;

    if (btn.classList.contains('text-accent-500')) {
        // Turn off
        btn.classList.remove('text-accent-500');
        btn.classList.add('text-gray-500');
        updateQuickTool();
    } else {
        // Turn on
        btn.classList.add('text-accent-500');
        btn.classList.remove('text-gray-500');

        // Simple Diff Logic
        const output = outputEl.innerText;
        // Just show side-by-side comparison for now as a simple diff view
        outputEl.innerHTML = `<div class="grid grid-cols-2 gap-4 text-xs"><div class="border-r border-white/10 pr-2"><div class="font-bold text-gray-500 mb-1">Input</div>${input}</div><div class="pl-2"><div class="font-bold text-gray-500 mb-1">Output</div>${output}</div></div>`;
    }
}

/**
 * Updates the output in the quick tool modal based on input.
 */
async function updateQuickTool() {
    if (!currentQuickToolKey) return;
    const input = document.getElementById('quick-tool-input').value;
    const outputEl = document.getElementById('quick-tool-output');
    const verifyInput = document.getElementById('quick-tool-verify-input');
    const password = document.getElementById('quick-tool-password').value || "OmniEncoder";
    const diffBtn = document.getElementById('btn-diff-toggle');
    if (diffBtn.classList.contains('text-accent-500')) return; // Don't overwrite if Diff is active

    try {
        if (currentMode === 'encode') {
            outputEl.innerText = await encoders[currentQuickToolKey].fn(input, password);
        } else {
            if (['sha1', 'sha256', 'sha512', 'crc32', 'adler32'].includes(currentQuickToolKey)) {
                const target = input.trim().toLowerCase();
                const source = verifyInput.value;
                if (!source) {
                    outputEl.innerHTML = '<span class="text-gray-500 italic">Enter original text to verify against the hash...</span>';
                } else {
                    const h = await encoders[currentQuickToolKey].fn(source);
                    if (h === target) {
                        outputEl.innerHTML = `<span class="text-emerald-400 font-bold">✅ MATCH CONFIRMED</span>\n\nInput Text: "${source}"\nCalculated: ${h}`;
                    } else {
                        outputEl.innerHTML = `<span class="text-red-400 font-bold">❌ NO MATCH</span>\n\nCalculated: ${h}\nTarget:     ${target}`;
                    }
                }
            } else {
                const res = decoders[currentQuickToolKey] ? await decoders[currentQuickToolKey](input, password) : "No decoder";
                if (typeof res === 'string' && res.startsWith('<div')) outputEl.innerHTML = res;
                else outputEl.innerText = res;
            }
        }
    } catch (e) {
        outputEl.innerText = "Error";
    }
}

/**
 * Sets up the file upload functionality by injecting a hidden file input
 * and an upload button next to the input label.
 */
function setupFileUpload() {
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.txt,text/plain';
    fileInput.style.display = 'none';
    document.body.appendChild(fileInput);

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            const file = e.target.files[0];
            if (!file.name.toLowerCase().endsWith('.txt') && file.type !== 'text/plain') {
                alert('Please select a text file (.txt).');
                return;
            }
            const reader = new FileReader();
            reader.onload = (evt) => {
                inputEl.value = evt.target.result;
                processText();
            };
            reader.readAsText(file);
        }
    });

    const label = document.querySelector('label[for="input-text"]');
    if (label) {
        label.style.display = 'inline-block';
        label.style.marginRight = '12px';

        const btn = document.createElement('button');
        btn.type = 'button';
        btn.innerHTML = '<svg class="w-4 h-4 inline-block mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg> Upload File';
        btn.className = "text-xs bg-white/5 hover:bg-white/10 text-gray-400 border border-white/10 px-3 py-1 rounded-full transition-all cursor-pointer inline-flex items-center hover:text-white hover:border-white/30";
        btn.onclick = (e) => { e.preventDefault(); fileInput.click(); };
        label.parentNode.insertBefore(btn, label.nextSibling);

        const clearBtn = document.createElement('button');
        clearBtn.type = 'button';
        clearBtn.innerHTML = 'Clear';
        clearBtn.className = "ml-2 text-xs bg-white/5 hover:bg-red-900/30 text-gray-400 border border-white/10 px-3 py-1 rounded-full transition-all cursor-pointer inline-flex items-center hover:text-red-400 hover:border-red-500/30";
        clearBtn.onclick = () => { inputEl.value = ''; processText(); };
        label.parentNode.insertBefore(clearBtn, btn.nextSibling);
    }
}

inputEl.addEventListener('input', debounce(processText, 400)); // Increased debounce for better performance

/**
 * Downloads the current chain result as a text file.
 */
function downloadResult() {
    const result = chainResultEl.innerText;
    if (!result || result.includes('Start typing')) return;
    const blob = new Blob([result], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `omniencoder_${currentMode}_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast();
}

/**
 * Exports current settings as a JSON file.
 */
function exportSettings() {
    const settings = {
        activeEncoders,
        chainSequence,
        bestMatchEnabled,
        theme: localStorage.getItem('omni_theme') || 'default',
        version: '3.1.0'
    };
    const blob = new Blob([JSON.stringify(settings, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `omniencoder_settings_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/**
 * Imports settings from a JSON file.
 */
function importSettings() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,application/json';
    input.onchange = async (e) => {
        if (e.target.files.length === 0) return;
        try {
            const text = await e.target.files[0].text();
            const settings = JSON.parse(text);
            if (settings.activeEncoders) {
                activeEncoders = settings.activeEncoders.filter(k => encoders[k]);
            }
            if (settings.chainSequence) {
                chainSequence = settings.chainSequence.filter(k => encoders[k]);
            }
            if (settings.theme) {
                applyTheme(settings.theme);
                const themeSelect = document.getElementById('theme-select');
                if (themeSelect) themeSelect.value = settings.theme;
            }
            if (typeof settings.bestMatchEnabled === 'boolean') {
                bestMatchEnabled = settings.bestMatchEnabled;
                localStorage.setItem('omni_best_match', bestMatchEnabled);
                const bestMatchToggle = document.getElementById('best-match-toggle');
                if (bestMatchToggle) bestMatchToggle.checked = bestMatchEnabled;
            }
            saveSettings();
            alert('Settings imported successfully!');
        } catch (err) {
            alert('Invalid settings file.');
        }
    };
    input.click();
}

/**
 * Keyboard shortcuts handler.
 */
document.addEventListener('keydown', (e) => {
    // Esc - Close modals
    if (e.key === 'Escape') {
        const settingsModal = document.getElementById('settings-modal');
        const quickModal = document.getElementById('quick-tool-modal');
        if (!settingsModal.classList.contains('hidden')) toggleSettings();
        if (!quickModal.classList.contains('hidden')) closeQuickTool();
    }

    // Ctrl+Enter - Copy chain result
    if (e.ctrlKey && e.key === 'Enter') {
        e.preventDefault();
        copyToClipboard('chain-result');
    }

    // Ctrl+D - Download result
    if (e.ctrlKey && e.key === 'd') {
        e.preventDefault();
        downloadResult();
    }

    // Ctrl+E - Toggle to Encode mode
    if (e.ctrlKey && !e.shiftKey && e.key === 'e') {
        e.preventDefault();
        setMode('encode');
    }

    // Ctrl+Shift+E - Toggle to Decode mode
    if (e.ctrlKey && e.shiftKey && e.key === 'E') {
        e.preventDefault();
        setMode('decode');
    }

    // Ctrl+/ - Show keyboard shortcuts help
    if (e.ctrlKey && e.key === '/') {
        e.preventDefault();
        alert('Keyboard Shortcuts:\\n\\n' +
            'Ctrl+Enter - Copy chain result\\n' +
            'Ctrl+D - Download result\\n' +
            'Ctrl+E - Encode mode\\n' +
            'Ctrl+Shift+E - Decode mode\\n' +
            'Esc - Close modals');
    }
});

window.addEventListener('DOMContentLoaded', () => {
    document.documentElement.lang = 'en';
    setupFileUpload();
    const params = new URLSearchParams(window.location.search);

    if (params.has('mode')) {
        const m = params.get('mode').toLowerCase();
        if (['encode', 'decode', 'auto', 'analyze'].includes(m)) currentMode = m;
    }

    if (params.has('encoders')) {
        const list = params.get('encoders').split(',').map(s => s.trim());
        const valid = list.filter(k => encoders[k]);
        if (valid.length > 0) activeEncoders = valid;
    }

    if (params.has('text')) {
        inputEl.value = params.get('text');
    }

    const currentTheme = localStorage.getItem('omni_theme') || 'default';
    applyTheme(currentTheme);
    const themeSelect = document.getElementById('theme-select');
    if (themeSelect) themeSelect.value = currentTheme;

    // Initialize Best Match toggle
    const bestMatchToggle = document.getElementById('best-match-toggle');
    if (bestMatchToggle) bestMatchToggle.checked = bestMatchEnabled;

    setMode(currentMode);
});