const AuthUtil = require('../lib/AuthUtil');
const assert = require('assert').strict;


describe('AuthUtil test', function () {
    const defaultValues = {
        defaultAlgorithm: 'sha512',
        defaultSecret: 'dev-secret',
        defaultOutputType: 'base64'
    };
    const authUtil = new AuthUtil(defaultValues);

    describe('Create random salt', function () {
        it('create the hash of string', function (done) {
            const test_hash = authUtil.createHmacString("some data to hash");
            assert.ok(test_hash, 'Hash not created');
            done();
        });

        it('creates a random salt string', function (done) {
            const salt = authUtil.createRandomSalt(new Date().valueOf().toString());
            assert.ok(salt, 'Salt is not created');
            done();
        });
    });

    describe('Encode and decode base64 string', function () {
        it('encode base64 string and reverse', function (done) {
            const myString = "some data to hash";
            const base64String = authUtil.asciiToBase64(myString);
            const unCodedString = authUtil.base64ToAscii(base64String);
            assert.equal(myString, unCodedString, 'both are not same');
            done();
        });
    });

    describe('Url safe and reverse url save', function () {
        it('url safe and reverse', function (done) {
            const myString = "some data to hash and some more";
            const base64String = authUtil.asciiToBase64(myString);
            const urlSafeString = authUtil.makeStringUrlSafe(base64String);
            const reversedUrlSafeString = authUtil.reverseStringUrlSafe(urlSafeString);
            assert.equal(base64String, reversedUrlSafeString, 'both are not same');
            done();
        });
    });

    describe('Create and split password hash', function () {
        it('create and split password', function (done) {
            const password = "password";
            const salt = authUtil.createRandomSalt(new Date().valueOf().toString());
            const passwordHash = authUtil.createPasswordHash(password, salt);
            const decomposedHash = authUtil.decomposePasswordHash(passwordHash);
            assert.equal(decomposedHash.algorithm, defaultValues.defaultAlgorithm, 'algorithm are not same');
            assert.equal(decomposedHash.salt, salt, 'salt are not same');
            done();
        });
    });

    describe('Create and verify password hash', function () {
        it('create and verify password', function (done) {
            const password = "my secret password";
            const badPassword = "bad password";
            const salt = authUtil.createRandomSalt(new Date().valueOf().toString());
            const passwordHash = authUtil.createPasswordHash(password, salt);
            const verified = authUtil.verifyPasswordHash(password, passwordHash);
            const unVerified = authUtil.verifyPasswordHash(badPassword, passwordHash);
            assert.equal(verified, true, 'both passwords are not same');
            assert.equal(unVerified, false, 'both passwords are same');
            done();
        });
    });
});