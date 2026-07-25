// revoke.js

// Stores whether the GitHub token has been revoked
let revoked = false;

/**
 * Revoke the GitHub token
 */
function revokeToken() {
    if (!revoked) {
        revoked = true;
        console.log("🚨 GitHub Token Revoked by ShadowGuard AI");
    }
}

/**
 * Check whether the token is revoked
 * @returns {boolean}
 */
function isTokenRevoked() {
    return revoked;
}

/**
 * Reset the token status for a new demo
 */
function resetToken() {
    revoked = false;
    console.log("✅ GitHub Token Reset Successfully");
}

module.exports = {
    revokeToken,
    isTokenRevoked,
    resetToken
};