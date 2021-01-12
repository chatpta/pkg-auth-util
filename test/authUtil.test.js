const AuthUtil = require('../lib/AuthUtil');
const assert = require('assert').strict;


describe('AuthUtil test', function () {
    const authUtil = new AuthUtil('sha512', 'dev-secret', 'base64');

    describe('Create random salt', function () {
        it('creates a random salt string', function (done) {
            const salt = authUtil.createRandomSalt(new Date().valueOf().toString());
            assert.ok(salt, 'Salt is not created');
            done();
        });
    });
});