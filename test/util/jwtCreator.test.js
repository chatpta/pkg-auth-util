const assert = require('assert').strict;
const index = require('../../index');


describe('JwtCreator test', function () {
    const auth = new index.JwtReader();

    describe('jwtCreate good input', function () {
        it('test true results of jwt create', function (done) {
            const header = {
                "alg": "sha512",
                "typ": "JWT"
            };
            const payload = {
                "sub": "1234567890",
                "name": "John Doe",
                "time": Date.now()
            };
            const secretKey = "my-secret-key";
            const jwt = auth.jwtCreate(header, payload, secretKey);
            const decryptedJWT = auth.jwtRead(jwt);
            assert.ok(auth.jwtIsSignatureValid(jwt, secretKey), 'Signature not valid');
            assert.ok(auth.jwtIsExpired(jwt, 1), 'Jwt is expired');
            assert.deepStrictEqual(decryptedJWT.payload.time, payload.time, 'Time is not same');
            done();
        });
    });

    describe('jwtCreate bad input', function () {
        it('test false results of jwt create and read', function (done) {
            const header = {
                "alg": "sha512",
                "typ": "JWT"
            };
            const payload = {
                "sub": "1234567890",
                "name": "John Doe",
                "time": (Date.now() - 2000)
            };
            const secretKey = "my-secret-key";
            const jwt = auth.jwtCreate(header, payload, secretKey);
            const jwtTempered = 'eyJhbGciOiJzaGE1MTILCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwidGltZSI6MTYxMDg0MTIyNTc4Nn0.146t2ctokZasu0g7InTYhYzq3_R2RbRvZevIHbPXTCP_BbP7NX31xxuDPXFdD2tQgtJLi15IrQHx80j7gHrHbQ';
            const verifiedTemperedJWT = auth.jwtIsSignatureValid(jwtTempered, secretKey);
            assert.ok(!verifiedTemperedJWT);
            const jwtExpired = auth.jwtIsExpired(jwt, 1);
            assert.ok(!jwtExpired, 'jwtIsExpired');
            const jwtDecrypted = auth.jwtRead(jwtTempered);
            assert.ok(!jwtDecrypted, 'return value is not null');
            done();
        });
    });

    describe('jwtCreateSHA512 good input', function () {
        it('test true results of jwt create', function (done) {
            const header = {};
            const payload = {
                "sub": "1234567890",
                "name": "John Doe",
                "time": Date.now()
            };
            const secretKey = "my-secret-key";
            const jwt = auth.jwtCreateSHA512(header, payload, secretKey);
            const decryptedJWT = auth.jwtRead(jwt);
            assert.ok(auth.jwtIsSignatureValid(jwt, secretKey), 'Signature not valid');
            assert.ok(auth.jwtIsExpired(jwt, 1), 'Jwt is expired');
            assert.deepStrictEqual(decryptedJWT.payload.time, payload.time, 'Time is not same');
            done();
        });
    });

    describe('headerPayloadUrlSafeStringCreate good input', function () {
        it('test url safe string', function (done) {
            const header = {
                "alg": "sha512",
                "typ": "JWT"
            };
            const payload = {
                "sub": "1234567890",
                "name": "John Doe",
                "time": Date.now()
            };
            const headerPayloadUrlSafe = auth.headerPayloadUrlSafeStringCreate(header, payload);
            assert.ok(headerPayloadUrlSafe.length > 100, 'Time is not same');
            done();
        });
    });
});