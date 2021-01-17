const AuthUtil = require('../lib/AuthUtil');
const JwtCreator = require('../lib/jwtCreator');
const JwtReader = require('../lib/jwtReader');
const assert = require('assert').strict;


describe('JwtCreator test', function () {
    const defaultValues = {
        defaultAlgorithm: 'sha512',
        defaultSecret: 'dev-secret',
        defaultOutputType: 'base64'
    };
    const authUtil = new AuthUtil(defaultValues);
    const jwtCreator = new JwtCreator(defaultValues);
    const jwtReader = new JwtReader(defaultValues);

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
            const jwt = jwtCreator.jwtCreate(header, payload, secretKey);
            const decryptedJWT = jwtReader.jwtRead(jwt);
            assert.ok(jwtReader.jwtIsSignatureValid(jwt, secretKey), 'Signature not valid');
            assert.ok(jwtReader.jwtIsExpired(jwt, 1), 'Jwt is expired');
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
            const jwt = jwtCreator.jwtCreate(header, payload, secretKey);
            const jwtTempered = 'eyJhbGciOiJzaGE1MTILCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwidGltZSI6MTYxMDg0MTIyNTc4Nn0.146t2ctokZasu0g7InTYhYzq3_R2RbRvZevIHbPXTCP_BbP7NX31xxuDPXFdD2tQgtJLi15IrQHx80j7gHrHbQ';
            const verifiedTemperedJWT = jwtReader.jwtIsSignatureValid(jwtTempered, secretKey);
            assert.ok(!verifiedTemperedJWT);
            const jwtExpired = jwtReader.jwtIsExpired(jwt, 1);
            assert.ok(!jwtExpired, 'jwtIsExpired');
            const jwtDecrypted = jwtReader.jwtRead(jwtTempered);
            assert.ok(!jwtDecrypted, 'return value is not null');
            done();
        });
    });

});