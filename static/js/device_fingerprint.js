/**
 * Simple Device Fingerprinting for Login Risk Assessment
 * Collects basic device characteristics to detect login from new devices
 */

function getDeviceFingerprint() {
    // Collect device characteristics
    const fingerprint = {
        userAgent: navigator.userAgent,
        language: navigator.language,
        platform: navigator.platform,
        hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
        deviceMemory: navigator.deviceMemory || 'unknown',
        maxTouchPoints: navigator.maxTouchPoints || 0,
        screenResolution: window.screen.width + 'x' + window.screen.height,
        screenColorDepth: window.screen.colorDepth,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        plugins: getPluginsList(),
    };

    // Create a simple hash
    const fingerString = JSON.stringify(fingerprint);
    return simpleHash(fingerString);
}

function getPluginsList() {
    // Get list of browser plugins
    if (!navigator.plugins) return [];
    const plugins = [];
    for (let i = 0; i < navigator.plugins.length; i++) {
        plugins.push(navigator.plugins[i].name);
    }
    return plugins.slice(0, 3); // Limit to first 3
}

function simpleHash(str) {
    // Simple hash function for fingerprint
    let hash = 0;
    if (str.length === 0) return hash.toString();
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash).toString(16);
}

// Inject fingerprint into login form on page load
document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.querySelector('form[action*="login"]');
    if (loginForm) {
        // Check if fingerprint input already exists
        if (!loginForm.querySelector('input[name="deviceFingerprint"]')) {
            const fingerprint = getDeviceFingerprint();
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'deviceFingerprint';
            input.value = fingerprint;
            loginForm.appendChild(input);
            console.log('[FINGERPRINT] Device fingerprint collected and added to form');
        }
    }
});
