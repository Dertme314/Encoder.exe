/**
 * Collection of encoder definitions.
 * Each encoder has a name, description, and a function `fn` that takes a string and returns the encoded string.
 */
const encoders = {
    base64: { name: "Base64", desc: "Binary-to-text encoding scheme", fn: (str) => { try { return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (m, p1) => String.fromCharCode('0x' + p1))); } catch (e) { return "Error"; } } },
    hex: { name: "Hexadecimal", desc: "Base-16 ASCII representation", fn: (str) => { let r = ''; for (let i = 0; i < str.length; i++) r += str.charCodeAt(i).toString(16).padStart(2, '0') + ' '; return r.trim(); } },
    octal: { name: "Octal", desc: "Base-8 number system", fn: (str) => { return str.split('').map(c => c.charCodeAt(0).toString(8).padStart(3, '0')).join(' '); } },
    binary: { name: "Binary", desc: "8-bit binary stream", fn: (str) => { return str.split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' '); } },
    rot13: { name: "ROT13", desc: "Simple letter substitution", fn: (str) => { return str.replace(/[a-zA-Z]/g, function (c) { return String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26); }); } },
    leet: { name: "1337 Speak", desc: "Alphanumeric substitution", fn: (str) => { const m = { 'a': '4', 'b': '8', 'e': '3', 'g': '9', 'l': '1', 'o': '0', 's': '5', 't': '7', 'z': '2', 'A': '4', 'B': '8', 'E': '3', 'G': '9', 'L': '1', 'O': '0', 'S': '5', 'T': '7', 'Z': '2' }; return str.split('').map(c => m[c] || c).join(''); } },
    atbash: { name: "Atbash", desc: "Reversed alphabet cipher", fn: (str) => { return str.replace(/[a-zA-Z]/g, (c) => { const k = c.charCodeAt(0); if (k >= 65 && k <= 90) return String.fromCharCode(90 - (k - 65)); if (k >= 97 && k <= 122) return String.fromCharCode(122 - (k - 97)); return c; }); } },
    nato: { name: "NATO Phonetic", desc: "Radiotelephony spelling", fn: (str) => { const n = { 'a': 'Alpha', 'b': 'Bravo', 'c': 'Charlie', 'd': 'Delta', 'e': 'Echo', 'f': 'Foxtrot', 'g': 'Golf', 'h': 'Hotel', 'i': 'India', 'j': 'Juliett', 'k': 'Kilo', 'l': 'Lima', 'm': 'Mike', 'n': 'November', 'o': 'Oscar', 'p': 'Papa', 'q': 'Quebec', 'r': 'Romeo', 's': 'Sierra', 't': 'Tango', 'u': 'Uniform', 'v': 'Victor', 'w': 'Whiskey', 'x': 'X-ray', 'y': 'Yankee', 'z': 'Zulu', '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three', '4': 'Four', '5': 'Five', '6': 'Six', '7': 'Seven', '8': 'Eight', '9': 'Nine' }; return str.toLowerCase().split('').map(c => n[c] ? n[c] : c).join(' '); } },
    htmlEnt: { name: "HTML Entities", desc: "Safe characters for web", fn: (str) => { return str.replace(/[\u00A0-\u9999<>\&]/g, (i) => '&#'+i.charCodeAt(0)+';'); } },
    url: { name: "URL Encoded", desc: "Percent-encoding for URLs", fn: (str) => encodeURIComponent(str) },
    reverse: { name: "Reverse", desc: "Reversed character order", fn: (str) => str.split('').reverse().join('') },
    ascii: { name: "ASCII", desc: "Decimal code points", fn: (str) => str.split('').map(c => c.charCodeAt(0)).join(', ') },
    morse: { name: "Morse Code", desc: "Telecommunication encoding", fn: (str) => { const m = { 'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', '0': '-----', ' ': '/', '.': '.-.-.-', ',': '--..--', '?': '..--..', '!': '-.-.--', '@': '.--.-.', '-': '-....-' }; return str.toUpperCase().split('').map(c => m[c] || c).join(' '); } }
};

/**
 * Collection of decoder definitions.
 * Each decoder takes a string and returns the decoded string.
 * Some decoders attempt to handle errors gracefully or return specific error messages.
 */
const decoders = {
    binary: (str) => {
        const clean = str.replace(/[^01 ]/g, '');
        const arr = clean.includes(' ') ? clean.split(' ') : (clean.match(/.{1,8}/g) || []);
        return arr.map(bin => String.fromCharCode(parseInt(bin, 2))).join('');
    },
    octal: (str) => {
        const clean = str.replace(/[^0-7 ]/g, '');
        const arr = clean.includes(' ') ? clean.split(' ') : (clean.match(/.{1,3}/g) || []);
        return arr.map(oct => String.fromCharCode(parseInt(oct, 8))).join('');
    },
    hex: (str) => {
        const clean = str.replace(/[^0-9A-Fa-f ]/g, '');
        const arr = clean.includes(' ') ? clean.split(' ') : (clean.match(/.{1,2}/g) || []);
        return arr.map(hex => String.fromCharCode(parseInt(hex, 16))).join('');
    },
    base64: (str) => { try { return decodeURIComponent(atob(str).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')); } catch (e) { try { return atob(str); } catch(e2) { return "Invalid Base64"; } } },
    rot13: (str) => encoders.rot13.fn(str),
    reverse: (str) => encoders.reverse.fn(str),
    url: (str) => decodeURIComponent(str),
    atbash: (str) => encoders.atbash.fn(str),
    htmlEnt: (str) => { const txt = document.createElement("textarea"); txt.innerHTML = str; return txt.value; },
    ascii: (str) => str.split(', ').map(c => String.fromCharCode(c)).join(''),
    nato: (str) => { const r = { 'Alpha': 'a', 'Bravo': 'b', 'Charlie': 'c', 'Delta': 'd', 'Echo': 'e', 'Foxtrot': 'f', 'Golf': 'g', 'Hotel': 'h', 'India': 'i', 'Juliett': 'j', 'Kilo': 'k', 'Lima': 'l', 'Mike': 'm', 'November': 'n', 'Oscar': 'o', 'Papa': 'p', 'Quebec': 'q', 'Romeo': 'r', 'Sierra': 's', 'Tango': 't', 'Uniform': 'u', 'Victor': 'v', 'Whiskey': 'w', 'X-ray': 'x', 'Yankee': 'y', 'Zulu': 'z', 'Zero': '0', 'One': '1', 'Two': '2', 'Three': '3', 'Four': '4', 'Five': '5', 'Six': '6', 'Seven': '7', 'Eight': '8', 'Nine': '9' }; return str.split(' ').map(w => { const k = w.charAt(0).toUpperCase() + w.slice(1).toLowerCase(); return r[k] || w; }).join(''); },
    morse: (str) => { const r = { '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z', '.----': '1', '..---': '2', '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9', '-----': '0', '/': ' ', '.-.-.-': '.', '--..--': ',', '..--..': '?', '-.-.--': '!', '.--.-.': '@', '-....-': '-' }; return str.split(' ').map(c => r[c] || c).join(''); },
    leet: (str) => { const r = { '4': 'a', '8': 'b', '3': 'e', '9': 'g', '1': 'l', '0': 'o', '5': 's', '7': 't', '2': 'z' }; return str.split('').map(c => r[c] || c).join(''); },
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
    const lines = text.length === 0 ? 0 : text.split(/\r\n|\r|\n/).length;
    const words = text.length === 0 ? 0 : text.trim().split(/\s+/).length;
    
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
            await new Promise(r => setTimeout(r, 10)); // Yield
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
                        el.innerText = encoders[key].fn(text); 
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
            if (isHeavy) {
                await new Promise(r => setTimeout(r, 10));
                updateProgress((completedSteps / totalSteps) * 100);
            }

            if (currentMode === 'encode') {
                if (encoders[key]) current = encoders[key].fn(current);
            } else {
                if (decoders[key]) current = decoders[key](current);
            }
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
    const checkboxes = document.querySelectorAll('#settings-encoders-grid input[type="checkbox"]');
    checkboxes.forEach(cb => cb.checked = select);
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
    
    title.innerText = `${encoders[key].name} ${currentMode === 'decode' ? '(Decode)' : '(Encode)'}`;
    input.value = inputEl.value; // Pre-fill with main input
    
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
function updateQuickTool() {
    if (!currentQuickToolKey) return;
    const input = document.getElementById('quick-tool-input').value;
    const outputEl = document.getElementById('quick-tool-output');
    
    try {
        if (currentMode === 'encode') {
            outputEl.innerText = encoders[currentQuickToolKey].fn(input);
        } else {
            outputEl.innerText = decoders[currentQuickToolKey] ? decoders[currentQuickToolKey](input) : "No decoder";
        }
    } catch (e) {
        outputEl.innerText = "Error";
    }
}

inputEl.addEventListener('input', debounce(processText, 300));
window.addEventListener('DOMContentLoaded', () => {
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