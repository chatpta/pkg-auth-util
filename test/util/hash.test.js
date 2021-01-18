const assert = require('assert').strict;
const index = require('../../index');


describe('Hash test', function () {

    const auth = new index.Auth();

    describe('createRandomSalt', function () {
        it('creates random salt', function (done) {
            const salt = auth.createRandomSalt();
            assert.ok(salt.length > 39);
            done();
        });
    });

    describe('createHmacString', function () {
        it('creates hmac string', async function () {
            const salt = await auth.createRandomSalt();
            const hmac = await auth.createHmacString(salt);
            assert.ok(hmac.length > 39);
        });
    });

    describe('createPasswordHashStoreString', function () {
        it('creates hash string to store', async function () {
            const password = "my-secret-password";
            const salt = await auth.createRandomSalt();
            const storeHashString = await auth.createPasswordHashStoreString(password, salt);
            assert.ok(storeHashString.length > 139);
        });
    });

    describe('verifyPasswordHash good input', function () {
        it('verifies hash against string to store', async function () {
            const password = "my-secret-password";
            const salt = await auth.createRandomSalt();
            const storeHashString = auth.createPasswordHashStoreString(password, salt);
            const verified = auth.verifyPasswordHash(password, storeHashString);
            assert.ok(verified);
        });
    });

    describe('verifyPasswordHash bad input', function () {
        it('verifies hash against string to store', async function () {
            const password = "my-secret-password";
            const badPassword = "my-bad-password";
            const salt = await auth.createRandomSalt();
            const storeHashString = await auth.createPasswordHashStoreString(password, salt);
            const verified = await auth.verifyPasswordHash(badPassword, storeHashString);
            assert.ok(!verified);
        });
    });

})