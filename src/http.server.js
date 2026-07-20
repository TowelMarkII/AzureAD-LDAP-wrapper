'use strict';

const http = require('node:http');
const helper = require('./helper');
const auth = require('./graph.auth');

function getBearerToken(req) {
    const header = req.headers['authorization'] || '';
    const match = /^Bearer (.+)$/.exec(header);
    return match ? match[1] : null;
}

// item 001 (.todo/001-jwt-http-endpoint.md) — routing/stub only. Real
// Graph validation is item 002, real rotation + secret-return is item 003.
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

        res.writeHead(501, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not implemented — see .todo/002 and .todo/003' }));
    } catch (error) {
        helper.error('http.server.js', 'jwt-login', error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'internal error' }));
    }
});

module.exports = httpServer;
