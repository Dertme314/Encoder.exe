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
 * Collection of encoder definitions.
 * Each encoder has a name, description, and a function `fn` that takes a string and returns the encoded string.
 */
const encoders = {
    base64: { name: "Base64", desc: "Binary-to-text encoding scheme", fn: (str) => { try { const bytes = new TextEncoder().encode(str); let binary = ''; for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]); return btoa(binary); } catch (e) { return "Error"; } } },
    hex: { name: "Hexadecimal", desc: "Base-16 ASCII representation", fn: (str) => { const bytes = new TextEncoder().encode(str); if (bytes.length === 0) return ''; let res = bytes[0].toString(16).padStart(2, '0'); for (let i = 1; i < bytes.length; i++) res += ' ' + bytes[i].toString(16).padStart(2, '0'); return res; } },
    octal: { name: "Octal", desc: "Base-8 number system", fn: (str) => { const bytes = new TextEncoder().encode(str); if (bytes.length === 0) return ''; let res = bytes[0].toString(8).padStart(3, '0'); for (let i = 1; i < bytes.length; i++) res += ' ' + bytes[i].toString(8).padStart(3, '0'); return res; } },
    binary: { name: "Binary", desc: "8-bit binary stream", fn: (str) => { const bytes = new TextEncoder().encode(str); if (bytes.length === 0) return ''; let res = bytes[0].toString(2).padStart(8, '0'); for (let i = 1; i < bytes.length; i++) res += ' ' + bytes[i].toString(2).padStart(8, '0'); return res; } },
    rot13: { name: "ROT13", desc: "Simple letter substitution", fn: (str) => { return str.replace(/[a-zA-Z]/g, function (c) { return String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26); }); } },
    leet: { name: "1337 Speak", desc: "Alphanumeric substitution", fn: (str) => { const m = { 'a': '4', 'b': '8', 'e': '3', 'g': '9', 'l': '1', 'o': '0', 's': '5', 't': '7', 'z': '2', 'A': '4', 'B': '8', 'E': '3', 'G': '9', 'L': '1', 'O': '0', 'S': '5', 'T': '7', 'Z': '2' }; return str.split('').map(c => m[c] || c).join(''); } },
    atbash: { name: "Atbash", desc: "Reversed alphabet cipher", fn: (str) => { return str.replace(/[a-zA-Z]/g, (c) => { const k = c.charCodeAt(0); if (k >= 65 && k <= 90) return String.fromCharCode(90 - (k - 65)); if (k >= 97 && k <= 122) return String.fromCharCode(122 - (k - 97)); return c; }); } },
    rot47: { name: "ROT47", desc: "ASCII shift-47 cipher", fn: (str) => str.replace(/[!-~]/g, function(c) { return String.fromCharCode(33 + ((c.charCodeAt(0) + 14) % 94)); }) },
    unicode: { name: "Unicode Escape", desc: "JS/Java escape sequences", fn: (str) => str.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('') },
    tap: { name: "Tap Code", desc: "Polybius square (C=K)", fn: (str) => { const p = "abcdefghijlmnopqrstuvwxyz"; return str.toLowerCase().split('').map(c => { if(c==='k') c='c'; const i = p.indexOf(c); if(i===-1) return c; return (Math.floor(i/5)+1) + '' + ((i%5)+1); }).join(' '); } },
    sha1: { name: "SHA-1", desc: "Secure Hash Algorithm 1", fn: (str) => hash('SHA-1', str) },
    sha256: { name: "SHA-256", desc: "Secure Hash Algorithm 256", fn: (str) => hash('SHA-256', str) },
    sha512: { name: "SHA-512", desc: "Secure Hash Algorithm 512", fn: (str) => hash('SHA-512', str) },
    crc32: { name: "CRC32", desc: "Cyclic Redundancy Check", fn: (str) => crc32(str) },
    adler32: { name: "Adler-32", desc: "Checksum algorithm (zlib)", fn: (str) => adler32(str) },
    nato: { name: "NATO Phonetic", desc: "Radiotelephony spelling", fn: (str) => { 
        const n = { 'a': 'alpha', 'b': 'bravo', 'c': 'charlie', 'd': 'delta', 'e': 'echo', 'f': 'foxtrot', 'g': 'golf', 'h': 'hotel', 'i': 'india', 'j': 'juliett', 'k': 'kilo', 'l': 'lima', 'm': 'mike', 'n': 'november', 'o': 'oscar', 'p': 'papa', 'q': 'quebec', 'r': 'romeo', 's': 'sierra', 't': 'tango', 'u': 'uniform', 'v': 'victor', 'w': 'whiskey', 'x': 'x-ray', 'y': 'yankee', 'z': 'zulu', '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three', '4': 'Four', '5': 'Five', '6': 'Six', '7': 'Seven', '8': 'Eight', '9': 'Nine' }; 
        return str.split('').map(c => {
            const lower = c.toLowerCase();
            if (!n[lower]) return c;
            const word = n[lower];
            // Preserve case: A -> ALPHA, a -> alpha
            return (c === lower) ? word : word.toUpperCase();
        }).join(' '); 
    } },
    htmlEnt: { name: "HTML Entities", desc: "Safe characters for web", fn: (str) => { return str.replace(/[\u00A0-\u9999<>\&]/g, (i) => '&#'+i.charCodeAt(0)+';'); } },
    url: { name: "URL Encoded", desc: "Percent-encoding for URLs", fn: (str) => encodeURIComponent(str) },
    reverse: { name: "Reverse", desc: "Reversed character order", fn: (str) => str.split('').reverse().join('') },
    ascii: { name: "ASCII", desc: "Decimal code points", fn: (str) => { if (str.length === 0) return ''; let res = '' + str.charCodeAt(0); for (let i = 1; i < str.length; i++) res += ', ' + str.charCodeAt(i); return res; } },
    morse: { name: "Morse Code", desc: "Telecommunication encoding", fn: (str) => { const m = { 'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', '0': '-----', ' ': '/', '.': '.-.-.-', ',': '--..--', '?': '..--..', '!': '-.-.--', '@': '.--.-.', '-': '-....-' }; return str.toUpperCase().split('').map(c => m[c] || c).join(' '); } }
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
            const bytes = Uint8Array.from(bin, c => c.charCodeAt(0));
            return new TextDecoder().decode(bytes);
        } catch (e) { 
            try { return atob(str); } catch(e2) { return "Invalid Base64"; } 
        } 
    },
    rot47: (str) => encoders.rot47.fn(str),
    unicode: (str) => str.replace(/\\u([0-9a-fA-F]{4})/g, (m, p1) => String.fromCharCode(parseInt(p1, 16))),
    tap: (str) => { const p = "abcdefghijlmnopqrstuvwxyz"; return str.split(' ').map(c => { if(c.length!==2 || isNaN(c)) return c; const r = parseInt(c[0])-1; const k = parseInt(c[1])-1; if(r<0||r>4||k<0||k>4) return c; return p[r*5+k]; }).join(''); },
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

let processingTask = 0;
const SLOW_THRESHOLD = 50000; // 50KB triggers slow mode
const progressContainer = document.getElementById('progress-container');
const progressBar = document.getElementById('progress-bar');
const heavyWarning = document.getElementById('heavy-load-warning');

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
let chainSequence = safeJSONParse('omni_chain_sequence', ['base64', 'reverse', 'rot13', 'hex', 'base64', 'octal', 'binary']);
let currentMode = localStorage.getItem('omni_mode') || 'encode';

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
    
    const activeClass = "px-8 py-3 rounded-lg font-bold text-sm transition-all duration-200 bg-accent-600/80 backdrop-blur-md text-white shadow-lg shadow-accent-500/20 border border-accent-500/50";
    const inactiveClass = "px-8 py-3 rounded-lg font-bold text-sm transition-all duration-200 bg-white/5 backdrop-blur-md text-gray-400 hover:bg-white/10 hover:text-white border border-white/5 hover:border-white/10";

    const appSections = ['input-section', 'tool-chain', 'encoders-section'];
    const docSection = document.getElementById('doc-section');

    if (mode === 'docs') {
        tabEncode.className = inactiveClass;
        tabDecode.className = inactiveClass;
        
        appSections.forEach(id => document.getElementById(id).classList.add('hidden'));
        bestMatchContainer.classList.add('hidden');
        bestMatchContainer.classList.remove('flex');
        
        docSection.classList.remove('hidden');
    } else {
        docSection.classList.add('hidden');
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
            <div class="flex justify-between items-start mb-3">
                <div>
                    <h3 class="font-bold text-gray-200 text-sm">${enc.name} ${currentMode === 'decode' ? '(Decode)' : ''}</h3>
                    <p class="text-[10px] text-gray-500 mt-0.5">${enc.desc}</p>
                </div>
                <button onclick="event.stopPropagation(); copyToClipboard('result-${key}')" class="text-gray-600 hover:text-white transition-colors p-1 opacity-50 group-hover:opacity-100" title="Copy">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7v8a2 2 0 002 2h6M8 7V5a2 2 0 012-2h4.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V15a2 2 0 01-2 2h-2M8 7H6a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2v-2"></path></svg>
                </button>
            </div>
            <div class="flex-grow bg-black/40 rounded border border-white/5 p-3 mt-1 shadow-inner">
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
        badge.className = `px-1.5 py-0.5 rounded bg-white/10 border border-white/5 text-gray-400 ${index === chainSequence.length - 1 ? 'text-accent-500 font-bold' : ''}`;
        badge.innerText = encoders[key] ? encoders[key].name.substring(0, 4) : key;
        chainVisualizerEl.appendChild(badge);
    });
}

/**
 * Attempts to find the best matching decoder for the given text based on heuristics.
 * @param {string} text - The encoded text.
 * @returns {string|null} The key of the best matching decoder, or null if no good match found.
 */
function findBestMatch(text) {
    if (!text || text.trim().length === 0) return null;
    
    let bestKey = null;
    let maxScore = 0;

    Object.keys(decoders).forEach(key => {
        // Skip transformations that don't imply a specific format
        if (key === 'reverse' || key === 'rot13' || key === 'atbash' || key === 'leet') return; 

        try {
            const decoded = decoders[key](text);
            if (!decoded || decoded === "Error" || decoded === "Invalid Base64") return;
            if (decoded === text) return; // No change means likely not a match

            let score = 0;
            const len = decoded.length;
            if (len === 0) return;

            // Heuristic 1: Printable characters ratio (is the output readable?)
            let printable = 0;
            for (let i = 0; i < len; i++) {
                const code = decoded.charCodeAt(i);
                if (code >= 32 && code <= 126) printable++;
            }
            const ratio = printable / len;
            if (ratio < 0.8) return; // Output looks like garbage

            score = ratio * 100;

            // Heuristic 2: Input format matching (Boost score for strict patterns)
            const t = text.trim();
            if (key === 'binary' && /^[01\s]+$/.test(t)) score += 100;
            if (key === 'hex' && /^[0-9A-Fa-f\s]+$/.test(t)) score += 80;
            if (key === 'octal' && /^[0-7\s]+$/.test(t)) score += 80;
            if (key === 'base64' && /^[A-Za-z0-9+/]+={0,2}$/.test(t) && t.length % 4 === 0) score += 90;
            if (key === 'morse' && /^[\.\-\/\s]+$/.test(t)) score += 150;
            if (key === 'htmlEnt' && /&[#a-zA-Z0-9]+;/.test(t)) score += 100;
            if (key === 'url' && /%[0-9A-F]{2}/i.test(t)) score += 100;
            if (key === 'unicode' && /\\u[0-9A-Fa-f]{4}/.test(t)) score += 100;
            if (key === 'tap' && /^([1-5]{2}\s*)+$/.test(t)) score += 100;

            if (score > maxScore) {
                maxScore = score;
                bestKey = key;
            }
        } catch (e) {}
    });

    return maxScore > 110 ? bestKey : null; // Threshold to avoid false positives on plain text
}

/**
 * Main processing function.
 * Handles input processing, chain execution, and parallel encoding/decoding.
 * Supports async execution with yielding for heavy loads to prevent UI freezing.
 */
async function processText() {
    const text = inputEl.value;
    const taskId = Date.now();
    processingTask = taskId;
    
    updateStats(text);
    
    const isHeavy = text.length > SLOW_THRESHOLD;
    if (isHeavy) {
        heavyWarning.classList.remove('hidden');
        updateProgress(0);
    } else {
        heavyWarning.classList.add('hidden');
        progressContainer.classList.add('hidden');
    }

    // Handle Best Match (Decode Mode Only)
    if (currentMode === 'decode') {
        const best = findBestMatch(text);
        if (best) {
            bestMatchContainer.classList.remove('hidden');
            bestMatchContainer.classList.add('flex');
            bestMatchName.innerText = encoders[best].name;
            bestMatchResult.innerText = decoders[best](text);
        } else {
            bestMatchContainer.classList.add('hidden');
            bestMatchContainer.classList.remove('flex');
        }
    } else {
        bestMatchContainer.classList.add('hidden');
        bestMatchContainer.classList.remove('flex');
    }

    const totalSteps = activeEncoders.length + chainSequence.length;
    let completedSteps = 0;

    // Parallel Encoders
    for (const key of activeEncoders) {
        if (processingTask !== taskId) return; // Cancelled
        
        if (isHeavy) {
            await new Promise(r => setTimeout(r, 0)); // Yield
            updateProgress((completedSteps / totalSteps) * 100);
        }

        const el = document.getElementById(`result-${key}`);
        if (el) {
            if (text.length === 0) {
                el.innerText = 'Waiting for input...';
                el.className = 'font-mono text-xs text-gray-600 italic h-20 overflow-y-auto pr-1';
            } else {
                try { 
                    if (currentMode === 'encode') {
                        el.innerText = await encoders[key].fn(text); 
                    } else {
                        el.innerText = decoders[key] ? decoders[key](text) : "No decoder";
                    }
                } catch(e) { el.innerText = "Error"; }
                el.className = 'font-mono text-xs text-gray-300 break-all h-20 overflow-y-auto pr-1';
            }
        }
        completedSteps++;
    }

    // Chain Logic
    if (text.length === 0) {
        chainResultEl.innerHTML = '<span class="text-gray-600 italic">Start typing to generate chain...</span>';
        if (isHeavy) updateProgress(100);
        return;
    }

    try {
        let current = text;
        const sequence = currentMode === 'encode' ? chainSequence : [...chainSequence].reverse();

        for (const key of sequence) {
            if (processingTask !== taskId) return;
            
            if (typeof current === 'string' && current.length > 20000000) {
                chainResultEl.innerText = "Chain output exceeded 20MB limit. Processing aborted to prevent browser crash.";
                if (isHeavy) updateProgress(100);
                return;
            }

            if (isHeavy) {
                await new Promise(r => setTimeout(r, 0));
                updateProgress((completedSteps / totalSteps) * 100);
            }

            let next = null;
            try {
                if (currentMode === 'encode') {
                    if (encoders[key]) next = await encoders[key].fn(current);
                    else next = current;
                } else {
                    if (decoders[key]) next = decoders[key](current);
                    else next = current; // Skip missing decoders (e.g. hashes)
                }
            } catch (e) { next = "Error"; }

            if (next && (typeof next === 'string') && (next.startsWith("Invalid") || next === "Error")) {
                chainResultEl.innerHTML = `<span class="text-red-400 font-bold">Chain Broken at step "${encoders[key]?.name || key}":</span> <span class="text-gray-400">${next}</span><br><span class="text-xs text-gray-500">The output from the previous step was incompatible with this module.</span>`;
                if (isHeavy) updateProgress(100);
                return;
            }
            current = next;
            completedSteps++;
        }
        chainResultEl.innerText = current;
    } catch (e) {
        chainResultEl.innerText = "Error in chain calculation.";
    }
    if (isHeavy) updateProgress(100);
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
    } catch (err) {}
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
    return function(...args) {
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
            chainSequence = Object.keys(encoders); 
            renderSettings(); 
            saveSettings(); 
        }
    };

    const btnChainClear = document.createElement('button');
    btnChainClear.innerText = 'Clear';
    btnChainClear.className = 'text-xs bg-white/5 hover:bg-red-900/30 text-gray-300 hover:text-red-400 border border-white/10 px-2 py-1 rounded transition-colors';
    btnChainClear.onclick = () => { if(confirm('Clear chain?')) { chainSequence = []; renderSettings(); saveSettings(); } };

    chainToolbar.appendChild(btnChainAddAll);
    chainToolbar.appendChild(btnChainClear);
    chainList.appendChild(chainToolbar);

    chainSequence.forEach((step, index) => {
        const div = document.createElement('div');
        div.className = 'flex justify-between items-center bg-white/5 p-2 rounded border border-white/10';
        div.innerHTML = `
            <span class="text-sm text-gray-300 font-mono"><span class="text-gray-600 mr-2">${index+1}.</span>${encoders[step]?.name || step}</span>
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
    if(confirm('Are you sure you want to reset all settings to default?')) {
        localStorage.removeItem('omni_active_encoders');
        localStorage.removeItem('omni_visible_tools');
        localStorage.removeItem('omni_chain_sequence');
        activeEncoders = Object.keys(encoders);
        visibleTools = { chain: true, hashing: true, decoder: true };
        chainSequence = ['base64', 'reverse', 'rot13', 'hex', 'base64', 'octal', 'binary'];
        renderSettings();
        saveSettings();
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
    const inputLabel = document.querySelector('label[for="quick-tool-input"]');
    
    title.innerText = `${encoders[key].name} ${currentMode === 'decode' ? '(Decode)' : '(Encode)'}`;
    input.value = inputEl.value; // Pre-fill with main input
    
    if (currentMode === 'decode' && ['sha1', 'sha256', 'sha512', 'crc32', 'adler32'].includes(key)) {
        verifySection.classList.remove('hidden');
        verifyInput.value = '';
        verifyInput.oninput = updateQuickTool;
        if(inputLabel) inputLabel.innerText = "Target Hash";
        title.innerText = `${encoders[key].name} (Verify)`;
    } else {
        verifySection.classList.add('hidden');
        if(inputLabel) inputLabel.innerText = "Input";
    }

    modal.classList.remove('hidden');
    updateQuickTool();
    
    input.oninput = updateQuickTool;
}

/**
 * Closes the quick tool modal.
 */
function closeQuickTool() {
    document.getElementById('quick-tool-modal').classList.add('hidden');
    currentQuickToolKey = null;
}

/**
 * Updates the output in the quick tool modal based on input.
 */
async function updateQuickTool() {
    if (!currentQuickToolKey) return;
    const input = document.getElementById('quick-tool-input').value;
    const outputEl = document.getElementById('quick-tool-output');
    const verifyInput = document.getElementById('quick-tool-verify-input');
    
    try {
        if (currentMode === 'encode') {
            outputEl.innerText = await encoders[currentQuickToolKey].fn(input);
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
                outputEl.innerText = decoders[currentQuickToolKey] ? decoderscurrentQuickToolKey : "No decoder";
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
    }
}

inputEl.addEventListener('input', debounce(processText, 300));
window.addEventListener('DOMContentLoaded', () => {
    setupFileUpload();
    const params = new URLSearchParams(window.location.search);
    
    if (params.has('mode')) {
        const m = params.get('mode').toLowerCase();
        if (m === 'encode' || m === 'decode') currentMode = m;
    }

    if (params.has('encoders')) {
        const list = params.get('encoders').split(',').map(s => s.trim());
        const valid = list.filter(k => encoders[k]);
        if (valid.length > 0) activeEncoders = valid;
    }

    if (params.has('text')) {
        inputEl.value = params.get('text');
    }

    setMode(currentMode);
});