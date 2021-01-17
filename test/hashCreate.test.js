const assert = require('assert').strict;
const HashCreate = require('../lib/hashCreate');


describe('HashCreator test', function () {
    const defaultValues = {
        defaultAlgorithm: 'sha512',
        defaultSecret: 'dev-secret',
        defaultOutputType: 'base64'
    };

    const hashCreate = new HashCreate(defaultValues);

    describe('createRandomSalt', function () {
        it('creates random salt', function (done) {
            const salt = hashCreate.createRandomSalt();
            assert.ok(salt.length > 39);
            done();
        });
    });

    describe('createHmacString', function () {
        it('creates hmac string', async function () {
            const salt = await hashCreate.createRandomSalt();
            const hmac = await hashCreate.createHmacString(salt);
            assert.ok(hmac.length > 39);
        });
    });

    describe('createPasswordHashStoreString', function () {
        it('creates hash string to store', async function () {
            const password = "my-secret-password";
            const salt = await hashCreate.createRandomSalt();
            const storeHashString = hashCreate.createPasswordHashStoreString(password, salt);
            assert.ok(storeHashString.length > 139);
        });
    });

    describe('verifyPasswordHash good input', function () {
        it('verifies hash against string to store', async function () {
            const password = "my-secret-password";
            const salt = await hashCreate.createRandomSalt();
            const storeHashString = hashCreate.createPasswordHashStoreString(password, salt);
            const verified = hashCreate.verifyPasswordHash(password, storeHashString);
            assert.ok(verified);
        });
    });

    describe('verifyPasswordHash bad input', function () {
        it('verifies hash against string to store', async function () {
            const password = "my-secret-password";
            const badPassword = "my-bad-password";
            const salt = await hashCreate.createRandomSalt();
            const storeHashString = hashCreate.createPasswordHashStoreString(password, salt);
            const verified = hashCreate.verifyPasswordHash(badPassword, storeHashString);
            assert.ok(!verified);
        });
    });

})