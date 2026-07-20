'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const config = require('./config');
const helper = require('./helper');
const auth = require('./graph.auth');
const database = require('./database');

function getBearerToken(req) {
    const header = req.headers['authorization'] || '';
    const match = /^Bearer (.+)$/.exec(header);
    return match ? match[1] : null;
}

function findUserEntryDN(db, username) {
    const claimed = (username || '').toString().toLowerCase();
    return Object.keys(db).find((dn) => {
        const entry = db[dn];
        return entry && typeof entry.AzureADuserPrincipalName === 'string'
            && entry.AzureADuserPrincipalName.toLowerCase() === claimed;
    }) || null;
}

// Generates a fresh random secret, sets it as the account's sambaNTPassword
// (same hashing server.js uses for a normal bind), and logs the rotation —
// unconditionally, plus a distinctly-flagged warning if it happened within
// JWT_ROTATION_RACE_WINDOW_SECONDS of the previous rotation for this user.
function rotateSecret(dn, username) {
    const db = database.getEntries();
    const userAttributes = db[dn];

    const secret = crypto.randomBytes(24).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const previousPwdLastSet = userAttributes.sambaPwdLastSet || 0;
    const deltaSeconds = previousPwdLastSet ? (now - previousPwdLastSet) : null;

    userAttributes.sambaNTPassword = helper.md4(secret);
    userAttributes.sambaPwdLastSet = now;

    if (config.LDAP_SAMBANTPWD_MAXCACHETIME != 0) {
        db[dn] = userAttributes;
        helper.SaveJSONtoFile(db, config.LDAP_DATAFILE);
    }

    helper.forceLog('http.server.js', 'rotateSecret', username, 'rotated', { deltaSeconds: deltaSeconds });

    if (deltaSeconds !== null && deltaSeconds < config.JWT_ROTATION_RACE_WINDOW_SECONDS) {
        helper.warn('http.server.js', 'rotateSecret', `POSSIBLE RACE: rapid re-rotation for user ${username}, ${deltaSeconds}s since last`);
    }

    return secret;
}

const httpServer = http.createServer(async (req, res) => {
    if (req.method !== 'POST' || !req.url.startsWith('/jwt-login')) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not found' }));
        return;
    }

    try {
        const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
        const username = url.searchParams.get('username');
        const jwt = getBearerToken(req);

        if (!helper.isJwtShaped(jwt)) {
            helper.log('http.server.js', 'jwt-login', username, 'not JWT-shaped -> 400');
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'credential is not JWT-shaped' }));
            return;
        }

        const check = await auth.validateJwtBind(username, jwt);
        helper.log('http.server.js', 'jwt-login', username, 'check', check);

        if (check !== 1) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'invalid credentials' }));
            return;
        }

        const dn = findUserEntryDN(database.getEntries(), username);
        if (!dn) {
            // same rejection as an invalid JWT — don't leak whether the user exists
            helper.error('http.server.js', 'jwt-login', username, 'validated but not found in local directory');
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'invalid credentials' }));
            return;
        }

        const secret = rotateSecret(dn, username);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ secret: secret }));
    } catch (error) {
        helper.error('http.server.js', 'jwt-login', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'internal error' }));
    }
});

module.exports = httpServer;
