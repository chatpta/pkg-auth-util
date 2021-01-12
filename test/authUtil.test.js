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
        it('creates a random salt string', function (done) {
            const salt = authUtil.createRandomSalt(new Date().valueOf().toString());
            assert.ok(salt, 'Salt is not created');
            done();
        });
    });
});