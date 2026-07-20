'use strict';

const http = require('node:http');
const fs = require('node:fs');

process.env["SKIP_DOTENV"] = "true";
process.env['LDAP_DATAFILE'] = './tests/tmp_http_server.test.json';
process.env['JWT_ROTATION_RACE_WINDOW_SECONDS'] = '5';

jest.mock('../src/graph.auth', () => ({
    validateJwtBind: jest.fn(async () => 0),
}));

let mockDb;
jest.mock('../src/database', () => ({
    getEntries: jest.fn(() => mockDb),
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

const validJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';

describe('http.server jwt-login endpoint', () => {
    beforeAll((done) => {
        jest.spyOn(console, 'log').mockImplementation(() => { });
        jest.spyOn(console, 'warn').mockImplementation(() => { });
        jest.spyOn(console, 'error').mockImplementation(() => { });
        process.env['LDAP_DEBUG'] = 'true';
        auth = require('../src/graph.auth');
        httpServer = require('../src/http.server');
        httpServer.listen(18080, '127.0.0.1', () => done());
    });

    afterAll((done) => {
        httpServer.close(() => {
            if (fs.existsSync('./tests/tmp_http_server.test.json')) {
                fs.unlinkSync('./tests/tmp_http_server.test.json');
            }
            done();
        });
        console.log.mockRestore();
        console.warn.mockRestore();
        console.error.mockRestore();
    });

    beforeEach(() => {
        auth.validateJwtBind.mockClear();
        console.warn.mockClear();
        mockDb = {
            'uid=alice,cn=users,dc=domain,dc=tld': {
                entryDN: 'uid=alice,cn=users,dc=domain,dc=tld',
                AzureADuserPrincipalName: 'alice@domain.tld',
                sambaNTPassword: 'OLDHASH0000000000000000000000000',
                sambaPwdLastSet: 0,
            },
        };
    });

    test('JWT-shaped credential routes to validateJwtBind, rejected -> 401', async () => {
        auth.validateJwtBind.mockResolvedValueOnce(0);

        const res = await request('/jwt-login?username=alice%40domain.tld', {
            headers: { authorization: `Bearer ${validJwt}` },
        });

        expect(res.statusCode).toBe(401);
        expect(auth.validateJwtBind).toHaveBeenCalledTimes(1);
        expect(auth.validateJwtBind).toHaveBeenCalledWith('alice@domain.tld', validJwt);
    });

    test('valid JWT for a user not found locally -> 401, no rotation', async () => {
        auth.validateJwtBind.mockResolvedValueOnce(1);

        const res = await request('/jwt-login?username=nobody%40domain.tld', {
            headers: { authorization: `Bearer ${validJwt}` },
        });

        expect(res.statusCode).toBe(401);
    });

    test('valid JWT for a known user -> 200 with rotated secret', async () => {
        auth.validateJwtBind.mockResolvedValueOnce(1);

        const res = await request('/jwt-login?username=alice%40domain.tld', {
            headers: { authorization: `Bearer ${validJwt}` },
        });

        expect(res.statusCode).toBe(200);
        const body = JSON.parse(res.body);
        expect(typeof body.secret).toBe('string');
        expect(body.secret.length).toBeGreaterThan(0);

        const entry = mockDb['uid=alice,cn=users,dc=domain,dc=tld'];
        expect(entry.sambaNTPassword).not.toBe('OLDHASH0000000000000000000000000');
        expect(entry.sambaPwdLastSet).toBeGreaterThan(0);
    });

    test('two rapid rotations for the same user log a POSSIBLE RACE warning', async () => {
        auth.validateJwtBind.mockResolvedValue(1);

        await request('/jwt-login?username=alice%40domain.tld', {
            headers: { authorization: `Bearer ${validJwt}` },
        });
        await request('/jwt-login?username=alice%40domain.tld', {
            headers: { authorization: `Bearer ${validJwt}` },
        });

        expect(console.warn.mock.calls.some((call) => call.join(' ').includes('POSSIBLE RACE'))).toBe(true);
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
