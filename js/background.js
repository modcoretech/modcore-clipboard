chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "save-secure",
        title: "Save to modcore (Secure)",
        contexts: ["selection"]
    });
});

chrome.contextMenus.onClicked.addListener((info) => {
    if (info.menuItemId === "save-secure" && info.selectionText) {
        addToPending(info.selectionText);
    }
});

chrome.runtime.onMessage.addListener((msg) => {
    if (msg.action === "autoSave" && msg.content) {
        addToPending(msg.content);
    }
});

async function addToPending(content) {
    // We cannot encrypt here because we don't have the PIN/Key.
    // We save to a "pending" queue.
    // The next time the user unlocks the popup, these are ingested and encrypted.
    
    const { pendingClips } = await chrome.storage.local.get('pendingClips');
    const list = pendingClips || [];
    
    // Simple duplicate check
    if (list.length > 0 && list[0].content === content) return;

    list.unshift({ content, timestamp: Date.now() });
    
    // Keep pending list small to avoid storage bloat (unencrypted)
    if (list.length > 20) list.pop();

    await chrome.storage.local.set({ pendingClips: list });
}
