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
        it('creates hmac string',  function (done) {
            const salt = auth.createRandomSalt();
            const hmac = auth.createHmacString(salt);
            assert.ok(hmac.length > 39);
            done();
        });
    });

    describe('createPasswordHashStoreString', function () {
        it('creates hash string to store', function (done) {
            const password = "my-secret-password";
            const salt = auth.createRandomSalt();
            const storeHashString = auth.createPasswordHashStoreString(password, salt);
            assert.ok(storeHashString.length > 139);
            done();
        });
    });

    describe('verifyPasswordHash good input', function () {
        it('verifies hash against string to store', function (done) {
            const password = "my-secret-password";
            const salt = auth.createRandomSalt();
            const storeHashString = auth.createPasswordHashStoreString(password, salt);
            const verified = auth.verifyPasswordHash(password, storeHashString);
            assert.ok(verified);
            done();
        });
    });

    describe('verifyPasswordHash bad input', function () {
        it('verifies hash against string to store', function (done) {
            const password = "my-secret-password";
            const badPassword = "my-bad-password";
            const salt = auth.createRandomSalt();
            const storeHashString = auth.createPasswordHashStoreString(password, salt);
            const verified = auth.verifyPasswordHash(badPassword, storeHashString);
            assert.ok(!verified);
            done();
        });
    });

})