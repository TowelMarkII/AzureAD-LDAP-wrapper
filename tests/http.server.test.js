'use strict';

const http = require('node:http');

jest.mock('../src/graph.auth', () => ({
    validateJwtBind: jest.fn(async () => 0),
}));

let httpServer;
let auth;

function request(path, { method = 'POST', headers = {} } = {}) {
    return new Promise((resolve, reject) => {
        const req = http.request({
            hostname: '127.0.0.1',
            port: 18080,
            path,
            method,
            headers,
        }, (res) => {
            let body = '';
            res.on('data', (chunk) => { body += chunk; });
            res.on('end', () => resolve({ statusCode: res.statusCode, body }));
        });
        req.on('error', reject);
        req.end();
    });
}

describe('http.server jwt-login endpoint', () => {
    beforeAll((done) => {
        jest.spyOn(console, 'log').mockImplementation(() => { });
        jest.spyOn(console, 'error').mockImplementation(() => { });
        process.env['LDAP_DEBUG'] = 'true';
        auth = require('../src/graph.auth');
        httpServer = require('../src/http.server');
        httpServer.listen(18080, '127.0.0.1', () => done());
    });

    afterAll((done) => {
        httpServer.close(() => done());
        console.log.mockRestore();
        console.error.mockRestore();
    });

    beforeEach(() => {
        auth.validateJwtBind.mockClear();
    });

    test('JWT-shaped credential routes to validateJwtBind, rejected -> 401', async () => {
        auth.validateJwtBind.mockResolvedValueOnce(0);

        const res = await request('/jwt-login?username=alice', {
            headers: { authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U' },
        });

        expect(res.statusCode).toBe(401);
        expect(auth.validateJwtBind).toHaveBeenCalledTimes(1);
        expect(auth.validateJwtBind).toHaveBeenCalledWith('alice', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U');
    });

    test('JWT-shaped credential routes to validateJwtBind, validated -> 501 (rotation not implemented)', async () => {
        auth.validateJwtBind.mockResolvedValueOnce(1);

        const res = await request('/jwt-login?username=alice', {
            headers: { authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U' },
        });

        expect(res.statusCode).toBe(501);
        expect(auth.validateJwtBind).toHaveBeenCalledTimes(1);
    });

    test('non-JWT-shaped credential responds 400 and does not call validateJwtBind', async () => {
        const res = await request('/jwt-login?username=alice', {
            headers: { authorization: 'Bearer mystrongpw' },
        });

        expect(res.statusCode).toBe(400);
        expect(auth.validateJwtBind).not.toHaveBeenCalled();
    });

    test('missing Authorization header responds 400 and does not call validateJwtBind', async () => {
        const res = await request('/jwt-login?username=alice');

        expect(res.statusCode).toBe(400);
        expect(auth.validateJwtBind).not.toHaveBeenCalled();
    });

    test('unknown route responds 404', async () => {
        const res = await request('/not-a-real-route', { method: 'GET' });

        expect(res.statusCode).toBe(404);
        expect(auth.validateJwtBind).not.toHaveBeenCalled();
    });
});
