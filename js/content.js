document.addEventListener('copy', async () => {
    const { monitoring } = await chrome.storage.local.get('monitoring');
    if (!monitoring) return;

    setTimeout(async () => {
        try {
            const text = await navigator.clipboard.readText();
            if (text && text.trim().length > 0) {
                chrome.runtime.sendMessage({
                    action: 'autoSave',
                    content: text
                });
            }
        } catch (e) {
            // Ignore permission errors
        }
    }, 200);
});
