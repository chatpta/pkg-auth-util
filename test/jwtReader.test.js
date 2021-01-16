const assert = require('assert').strict;
const AuthUtil = require('../lib/AuthUtil');
const JwtReader = require('../lib/jwtReader');


describe('JwtReader test', function () {
    const defaultValues = {
        defaultAlgorithm: 'sha512',
        defaultSecret: 'dev-secret',
        defaultOutputType: 'base64'
    };
    const authUtil = new AuthUtil(defaultValues);
    const jwtReader = new JwtReader(defaultValues);

    describe('jwtIsExpired', function () {
        it('create and verify jwt', function (done) {
            const header = {
                "alg": "sha512",
                "typ": "JWT"
            };
            const payload = {
                "id": "1234567890",
                "time": Date.now()
            };
            const payloadOld = {
                "id": "1234567890",
                "time": (Date.now() - 60005)
            };
            const secretKey = "my-secret-key";
            const jwtFresh = authUtil.createJWT(header, payload, secretKey);
            const jwtOld = authUtil.createJWT(header, payloadOld, secretKey);
            const validNew = jwtReader.jwtIsExpired(jwtFresh, 60);
            const validOld = jwtReader.jwtIsExpired(jwtOld, 60);
            assert.equal(validNew, true, 'jwt verified');
            assert.equal(validOld, false, 'jwt not verified');
            done();
        });
    });

    describe('jwtIsSignatureValid', function () {
        it('create and verify jwt', function (done) {
            const header = {
                "alg": "sha512",
                "typ": "JWT"
            };
            const payload = {
                "id": "1234567890",
                "time": Date.now()
            };
            const secretKey = "my-secret-key";
            const jwt = authUtil.createJWT(header, payload, secretKey);
            const verified = jwtReader.jwtIsSignatureValid(jwt, secretKey);
            const unVerified = jwtReader.jwtIsSignatureValid((jwt + 'she'), secretKey);
            assert.equal(verified, true, 'jwt verified');
            assert.equal(unVerified, false, 'jwt not verified');
            done();
        });
    });

    describe('jwtRead', function () {
        it('read jwt into an object', function (done) {
            const header = {
                "alg": "sha512",
                "typ": "JWT"
            };
            const payload = {
                "id": "1234567890",
                "time": Date.now()
            };
            const secretKey = "my-secret-key";
            const jwt = authUtil.createJWT(header, payload, secretKey);
            const jwtObject = jwtReader.jwtRead(jwt);
            assert.equal(JSON.stringify(jwtObject.header),
                JSON.stringify(header), 'jwt not equal');
            done();
        });
    });
});