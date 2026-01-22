/**
 * modcore Clipboard Manager
 * Version 2.1 - Zero-Knowledge, Robust, Image Support
 */

// --- CRYPTOGRAPHY MODULE ---
const CryptoCore = {
    config: {
        algo: { name: 'AES-GCM', length: 256 },
        pbkdf2: { name: 'PBKDF2', hash: 'SHA-256', iterations: 200000 }, // Increased iterations for security
        saltLen: 16
    },

    generateSalt() {
        return window.crypto.getRandomValues(new Uint8Array(this.config.saltLen));
    },

    async deriveKey(pin, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw', enc.encode(pin), { name: 'PBKDF2' }, false, ['deriveKey']
        );
        return window.crypto.subtle.deriveKey(
            { ...this.config.pbkdf2, salt: salt },
            keyMaterial,
            this.config.algo,
            false,
            ['encrypt', 'decrypt']
        );
    },

    async encrypt(data, key) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Unique IV per encryption
        const enc = new TextEncoder();
        const encodedData = enc.encode(JSON.stringify(data));
        
        const encryptedContent = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv }, key, encodedData
        );

        return {
            iv: Array.from(iv),
            content: Array.from(new Uint8Array(encryptedContent))
        };
    },

    async decrypt(encryptedObj, key) {
        const iv = new Uint8Array(encryptedObj.iv);
        const data = new Uint8Array(encryptedObj.content);

        try {
            const decryptedContent = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv }, key, data
            );
            const dec = new TextDecoder();
            return JSON.parse(dec.decode(decryptedContent));
        } catch (e) {
            throw new Error('Decryption failed. Invalid PIN or corrupted data.');
        }
    }
};

// --- STATE MANAGEMENT ---
const State = {
    key: null,          // CryptoKey (Session only)
    snippets: [],       // Decrypted data
    searchQuery: '',
    pagination: { page: 1, perPage: 15 },
    pendingEditId: null,
    currentEditType: 'text', // 'text' | 'image'
    currentImageData: null   // Base64 string if type is image
};

// --- DOM UTILS ---
const el = (id) => document.getElementById(id);
const views = {
    auth: el('view-auth'),
    onboarding: el('view-onboarding'),
    dashboard: el('view-dashboard')
};

// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', async () => {
    bindEvents();
    
    const isSetup = await checkSetup();
    if (isSetup) {
        showView('auth');
        el('auth-pin').focus();
    } else {
        showView('onboarding');
    }
});

function bindEvents() {
    // Auth
    el('login-form').addEventListener('submit', handleLogin);
    el('setup-form').addEventListener('submit', handleSetup);
    el('forgot-pin-btn').addEventListener('click', () => confirmAction(
        'Reset App?', 
        'This will erase all encrypted data permanently. There is no way to recover data without the PIN.', 
        handleReset
    ));

    // Dashboard
    el('add-snippet-btn').addEventListener('click', () => openEditModal());
    el('settings-btn').addEventListener('click', () => el('modal-settings').classList.add('open'));
    el('search-input').addEventListener('input', handleSearch);

    // Edit Modal
    el('close-modal').addEventListener('click', () => el('modal-edit').classList.remove('open'));
    el('save-snippet-btn').addEventListener('click', saveSnippet);
    el('edit-content').addEventListener('paste', handlePaste);
    el('remove-image-btn').addEventListener('click', clearImagePreview);

    // Settings
    el('close-settings').addEventListener('click', () => el('modal-settings').classList.remove('open'));
    el('reset-app-btn').addEventListener('click', () => confirmAction('Danger Zone', 'Reset app and wipe all data?', handleReset));
    
    // Change PIN
    el('change-pin-btn').addEventListener('click', () => el('modal-change-pin').classList.add('open'));
    el('close-change-pin').addEventListener('click', () => el('modal-change-pin').classList.remove('open'));
    el('change-pin-form').addEventListener('submit', handleChangePin);

    // Import/Export
    el('export-data-btn').addEventListener('click', handleExport);
    el('import-data-btn').addEventListener('click', () => el('import-file-input').click());
    el('import-file-input').addEventListener('change', handleImport);

    // Monitor Toggle
    el('toggle-monitor').addEventListener('change', (e) => {
        chrome.storage.local.set({ monitoring: e.target.checked });
    });
    
    // Load Monitor State
    chrome.storage.local.get('monitoring', (r) => el('toggle-monitor').checked = !!r.monitoring);
}

// --- VIEW CONTROLLER ---
function showView(viewName) {
    Object.values(views).forEach(v => v.classList.remove('active'));
    views[viewName].classList.add('active');
}

async function checkSetup() {
    const data = await chrome.storage.local.get(['salt', 'encryptedData']);
    return !!data.salt;
}

// --- AUTH LOGIC ---

async function handleSetup(e) {
    e.preventDefault();
    const pin = el('setup-pin').value;
    const confirm = el('setup-pin-confirm').value;

    if (!validatePin(pin)) return;
    if (pin !== confirm) return showToast('PINs do not match', 'error');

    try {
        setLoading(true);
        const salt = CryptoCore.generateSalt();
        const key = await CryptoCore.deriveKey(pin, salt);
        const encrypted = await CryptoCore.encrypt([], key); // Init empty

        await chrome.storage.local.set({
            salt: Array.from(salt),
            encryptedData: encrypted
        });

        State.key = key;
        State.snippets = [];
        showView('dashboard');
        renderSnippets();
    } catch (err) {
        showToast('Setup failed: ' + err.message, 'error');
    } finally {
        setLoading(false);
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const pin = el('auth-pin').value;
    if (!pin) return;

    try {
        setLoading(true);
        const { salt, encryptedData } = await chrome.storage.local.get(['salt', 'encryptedData']);
        if (!salt) return showView('onboarding');

        const saltUint = new Uint8Array(salt);
        const key = await CryptoCore.deriveKey(pin, saltUint);
        
        // Decrypt
        const snippets = await CryptoCore.decrypt(encryptedData, key);
        
        // Success
        State.key = key;
        State.snippets = snippets;
        
        // Process background auto-saves
        await processPendingClips();
        
        showView('dashboard');
        renderSnippets();
        el('auth-pin').value = ''; // Clear memory
    } catch (err) {
        console.error(err);
        const input = el('auth-pin');
        input.classList.add('shake');
        input.value = '';
        showToast('Incorrect PIN', 'error');
        setTimeout(() => input.classList.remove('shake'), 500);
    } finally {
        setLoading(false);
    }
}

async function handleChangePin(e) {
    e.preventDefault();
    const p1 = el('new-pin').value;
    const p2 = el('new-pin-confirm').value;

    if (!validatePin(p1)) return;
    if (p1 !== p2) return showToast('PINs do not match', 'error');

    try {
        setLoading(true);
        // 1. Generate new Salt
        const newSalt = CryptoCore.generateSalt();
        // 2. Derive new Key
        const newKey = await CryptoCore.deriveKey(p1, newSalt);
        // 3. Encrypt current data with new Key
        const newEncryptedData = await CryptoCore.encrypt(State.snippets, newKey);

        // 4. Save
        await chrome.storage.local.set({
            salt: Array.from(newSalt),
            encryptedData: newEncryptedData
        });

        State.key = newKey; // Update session key
        el('modal-change-pin').classList.remove('open');
        el('new-pin').value = '';
        el('new-pin-confirm').value = '';
        showToast('PIN changed & data re-encrypted successfully');
    } catch(err) {
        showToast('Error changing PIN', 'error');
    } finally {
        setLoading(false);
    }
}

// --- SNIPPET LOGIC ---

async function saveSnippet() {
    let content = el('edit-content').value.trim();
    
    // Validation: Require content OR image
    if (!content && !State.currentImageData) {
        return showToast('Snippet cannot be empty', 'error');
    }

    const newSnippet = {
        id: State.pendingEditId || crypto.randomUUID(),
        type: State.currentImageData ? 'image' : 'text',
        content: State.currentImageData || content, // Store image data if exists, else text
        metaText: State.currentImageData ? content : null, // Optional caption for images
        tags: [],
        date: Date.now()
    };

    if (State.pendingEditId) {
        const idx = State.snippets.findIndex(s => s.id === State.pendingEditId);
        if (idx !== -1) State.snippets[idx] = newSnippet;
    } else {
        State.snippets.unshift(newSnippet);
    }

    await saveEncrypted();
    el('modal-edit').classList.remove('open');
    renderSnippets();
    showToast('Snippet saved securely');
}

async function deleteSnippet(id) {
    confirmAction('Delete Snippet?', 'This cannot be undone.', async () => {
        State.snippets = State.snippets.filter(s => s.id !== id);
        await saveEncrypted();
        renderSnippets();
        showToast('Snippet deleted');
    });
}

async function saveEncrypted() {
    if (!State.key) return;
    try {
        const encrypted = await CryptoCore.encrypt(State.snippets, State.key);
        await chrome.storage.local.set({ encryptedData: encrypted });
    } catch (e) {
        showToast('Save failed: Storage error', 'error');
    }
}

// --- IMAGE HANDLING & PASTE ---

function handlePaste(e) {
    const items = (e.clipboardData || e.originalEvent.clipboardData).items;
    
    for (const item of items) {
        if (item.type.indexOf('image') === 0) {
            e.preventDefault();
            const blob = item.getAsFile();
            const reader = new FileReader();
            
            reader.onload = function(event) {
                State.currentImageData = event.target.result;
                State.currentEditType = 'image';
                
                const img = el('edit-image-preview');
                img.src = State.currentImageData;
                el('edit-image-preview-container').classList.remove('hidden');
                el('edit-content').placeholder = "Add a caption (optional)...";
            };
            
            reader.readAsDataURL(blob);
            return; // Stop after first image
        }
    }
}

function clearImagePreview() {
    State.currentImageData = null;
    State.currentEditType = 'text';
    el('edit-image-preview').src = "";
    el('edit-image-preview-container').classList.add('hidden');
    el('edit-content').placeholder = "Type text or Paste (Ctrl+V) an image...";
}

// --- RENDERER ---

function renderSnippets() {
    const list = el('snippet-list');
    list.innerHTML = '';

    const query = State.searchQuery.toLowerCase();
    const filtered = State.snippets.filter(s => {
        const textToCheck = s.type === 'image' ? (s.metaText || 'image') : s.content;
        return textToCheck.toLowerCase().includes(query);
    });

    const limit = State.pagination.page * State.pagination.perPage;
    const pageItems = filtered.slice(0, limit);

    if (pageItems.length === 0) {
        list.innerHTML = `<div class="empty-state">No snippets found</div>`;
        return;
    }

    pageItems.forEach(snip => {
        const div = document.createElement('div');
        div.className = 'snippet-card';
        
        let contentHtml = '';
        if (snip.type === 'image') {
            contentHtml = `
                <div class="snippet-image-container">
                    <img src="${snip.content}" class="snippet-img">
                </div>
                ${snip.metaText ? `<div class="snippet-caption">${escapeHtml(snip.metaText)}</div>` : ''}
            `;
        } else {
            contentHtml = `<div class="snippet-text">${escapeHtml(snip.content)}</div>`;
        }

        div.innerHTML = `
            ${contentHtml}
            <div class="snippet-actions">
                <button class="btn action-btn copy-btn" aria-label="Copy"><i class="icon i-copy"></i></button>
                <button class="btn action-btn edit-btn" aria-label="Edit"><i class="icon i-edit"></i></button>
                <button class="btn action-btn delete-btn" aria-label="Delete"><i class="icon i-trash"></i></button>
            </div>
        `;
        
        // Handlers
        div.querySelector('.copy-btn').addEventListener('click', () => {
             if(snip.type === 'image') copyImageToClipboard(snip.content);
             else copyTextToClipboard(snip.content);
        });
        div.querySelector('.edit-btn').addEventListener('click', () => openEditModal(snip.id));
        div.querySelector('.delete-btn').addEventListener('click', () => deleteSnippet(snip.id));
        
        list.appendChild(div);
    });
}

function openEditModal(id = null) {
    const modal = el('modal-edit');
    const contentInput = el('edit-content');
    
    State.pendingEditId = id;
    clearImagePreview();
    
    if (id) {
        const snip = State.snippets.find(s => s.id === id);
        if (snip.type === 'image') {
            State.currentImageData = snip.content;
            State.currentEditType = 'image';
            el('edit-image-preview').src = snip.content;
            el('edit-image-preview-container').classList.remove('hidden');
            contentInput.value = snip.metaText || '';
        } else {
            contentInput.value = snip.content;
        }
        el('modal-title').textContent = "Edit Snippet";
    } else {
        contentInput.value = '';
        el('modal-title').textContent = "New Snippet";
    }
    
    modal.classList.add('open');
    contentInput.focus();
}

// --- UTILS & HELPERS ---

async function copyTextToClipboard(text) {
    await navigator.clipboard.writeText(text);
    showToast("Text copied!");
}

async function copyImageToClipboard(base64) {
    try {
        const res = await fetch(base64);
        const blob = await res.blob();
        await navigator.clipboard.write([
            new ClipboardItem({ [blob.type]: blob })
        ]);
        showToast("Image copied!");
    } catch (e) {
        showToast("Failed to copy image", "error");
    }
}

function handleSearch(e) {
    State.searchQuery = e.target.value;
    State.pagination.page = 1;
    renderSnippets();
}

async function processPendingClips() {
    const { pendingClips } = await chrome.storage.local.get('pendingClips');
    if (!pendingClips || pendingClips.length === 0) return;

    let count = 0;
    pendingClips.forEach(clip => {
        // Prevent dupes
        if (!State.snippets.some(s => s.content === clip.content)) {
            State.snippets.unshift({
                id: crypto.randomUUID(),
                type: 'text',
                content: clip.content,
                tags: ['auto'],
                date: Date.now()
            });
            count++;
        }
    });

    if (count > 0) {
        await saveEncrypted();
        await chrome.storage.local.remove('pendingClips');
        showToast(`${count} items auto-saved`);
    }
}

function validatePin(pin) {
    if (!/^\d{6}$/.test(pin)) {
        showToast('PIN must be exactly 6 digits', 'error');
        return false;
    }
    return true;
}

// --- DATA IMPORT / EXPORT ---

function handleExport() {
    if (!State.snippets.length) return showToast("Nothing to export");
    
    const dataStr = JSON.stringify(State.snippets, null, 2);
    const blob = new Blob([dataStr], {type: "application/json"});
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `modcore-backup-${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function handleImport(e) {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (event) => {
        try {
            const imported = JSON.parse(event.target.result);
            if (!Array.isArray(imported)) throw new Error("Invalid format");
            
            confirmAction('Import Data', `Merge ${imported.length} snippets? duplicates will be skipped.`, async () => {
                let added = 0;
                imported.forEach(item => {
                    if (!item.content || !item.type) return;
                    // Check duplicate
                    if (!State.snippets.some(s => s.content === item.content)) {
                        // Sanitize structure
                        item.id = crypto.randomUUID(); 
                        State.snippets.push(item);
                        added++;
                    }
                });
                
                await saveEncrypted();
                renderSnippets();
                showToast(`Imported ${added} snippets`);
                el('modal-settings').classList.remove('open');
            });
        } catch (err) {
            showToast("Invalid JSON file", "error");
        }
    };
    reader.readAsText(file);
    e.target.value = ''; // reset
}

async function handleReset() {
    await chrome.storage.local.clear();
    location.reload();
}

// --- UI COMPONENTS ---

function escapeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function showToast(msg, type = 'success') {
    const toast = document.createElement('div');
    toast.textContent = msg;
    toast.className = `toast toast-${type}`;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

function confirmAction(title, text, onConfirm) {
    const dialog = el('custom-dialog');
    el('dialog-title').textContent = title;
    el('dialog-text').textContent = text;
    
    const confirmBtn = el('dialog-confirm');
    const cancelBtn = el('dialog-cancel');
    
    // Clean previous listeners
    const newConfirm = confirmBtn.cloneNode(true);
    const newCancel = cancelBtn.cloneNode(true);
    confirmBtn.parentNode.replaceChild(newConfirm, confirmBtn);
    cancelBtn.parentNode.replaceChild(newCancel, cancelBtn);

    dialog.classList.remove('hidden');

    newConfirm.addEventListener('click', () => {
        onConfirm();
        dialog.classList.add('hidden');
    });

    newCancel.addEventListener('click', () => {
        dialog.classList.add('hidden');
    });
}

function setLoading(isLoading) {
    const btns = document.querySelectorAll('button');
    btns.forEach(b => b.disabled = isLoading);
    document.body.style.cursor = isLoading ? 'wait' : 'default';
}
