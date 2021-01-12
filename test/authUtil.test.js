const AuthUtil = require('../lib/AuthUtil');
const assert = require('assert').strict;


describe('AuthUtil test', function () {
    const authUtil = new AuthUtil();

    describe('Create random salt', function () {
        it('creates a random salt string', function (done) {
            const salt = authUtil.createRandomSalt();
            assert.ok(salt, 'Salt is not created');
            done();
        });
    });
});