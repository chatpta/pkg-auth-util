const assert = require('assert');
const index = require('../../index');

const defaultValues = {
    defaultAlgorithm: 'sha512',
    defaultSecret: 'dev-secret',
    defaultOutputType: 'base64'
};

const middleware = new index.Middleware();
// const jwtReader = new index.JwtReader(defaultValues);
// const jwtCreator = new index.JwtCreator(defaultValues);
const hash = new index.Hash(defaultValues);
// const validata = new index.Validate();


describe('Middleware tests', () => {
    let nextFunc = function (req, res) {
    };
    let res = {
        json: (obj) => res.body = obj
    };
    let req;
    beforeEach(() => {
        req = {};
    });

    after(async () => {

    });

    describe('test function createHeaderPayloadForJwtFromReqUserSHA512', () => {
        it('create header', async () => {
            req.user = {user_id: 123456789};
            await middleware.createJwtHeaderPayloadForJwtFromReqUserSHA512(req, res, nextFunc);
            assert.ok(!!req.jwtPayload.user_id,
                'user_id not there');
        });
    });

    describe('test function createJwtTokenSHA512', () => {
        it('create jwt token', async () => {
            req.user = {user_id: 123456789};
            await middleware.createJwtHeaderPayloadForJwtFromReqUserSHA512(req, res, nextFunc);
            await middleware.createJwtTokenSHA512(req, req, nextFunc);
            assert.ok(!req.jwtPayload, 'payload is not consumed');
            assert.ok(req.jwtToken.length > 100, 'jwtToken not created');
        });
    });

    describe('test function sendJwtInReply', () => {
        it('sends jwt token', async () => {
            req.user = {user_id: 123456789};
            await middleware.createJwtHeaderPayloadForJwtFromReqUserSHA512(req, res, nextFunc);
            await middleware.createJwtTokenSHA512(req, req, nextFunc);
            await middleware.sendJwtInReply(req, res, nextFunc);
            assert.ok((res.body.jwt.length > 100), 'not returning jwt');
        });
    });

    describe('test function validatePasswordInReqBodyPassword', () => {
        it('validatePassword', async () => {
            req = {
                body: {
                    password: "secre*77newpass"
                }
            };
            await middleware.validatePasswordInReqBodyPassword(req, res, nextFunc);
            assert.ok(req.incomingUser.password.length > 5, 'Problem in validatePassword');
        });

        it('validatePassword should fail', async () => {
            req = {
                body: {
                    password: "bad pass"
                }
            };
            await middleware.validatePasswordInReqBodyPassword(req, res, nextFunc);
            assert.ok(!req.incomingUser.password, 'Should be problem in validatePassword');
        });
    });

    describe('test function validatePasswordInReqBodyPassword', () => {
        it('valid Email', async () => {
            req = {
                body: {
                    email: "validUsernamePassTest@gmail.com"
                }
            };
            await middleware.validateEmailInReqBodyEmail(req, res, nextFunc);
            assert.ok(req.incomingUser.email.length > 5, 'Problem in valid Email');
        });

        it('not valid Email', async () => {
            req = {
                body: {
                    email: "validUsernamePassTestgmail.com"
                }
            };
            await middleware.validateEmailInReqBodyEmail(req, res, nextFunc);
            assert.ok(!req.incomingUser.email, 'Problem in not valid Email');
        });
    });

    describe('test function email password move to req.user from req.databaseUser', () => {
        it('move user_id', async () => {
            req = {
                databaseUser: {
                    email: "validUsernamePassTest@gmail.com",
                    user_id: 123456788,
                    hash: "somethisnf827273shseoe"
                }
            };
            await middleware.moveReqDatabaseUserIdToReqUserId(req, res, nextFunc);
            assert.ok(!req.databaseUser.user_id, 'Problem in user_id');
            assert.ok(req.user.user_id, 'Problem in user_id');
        });

        it('move email', async () => {
            req = {
                databaseUser: {
                    email: "validUsernamePassTest@gmail.com",
                    user_id: 123456788,
                    hash: "somethisnf827273shseoe"
                }
            };
            await middleware.moveReqDatabaseUserEmailToReqUserEmail(req, res, nextFunc);
            assert.ok(!req.databaseUser.email, 'Problem in email');
            assert.ok(req.user.email, 'Problem in email');
        });

        it('move email problem', async () => {
            req = {
                databaseUser: {
                    email: "validUsernamePassTest@gmail.com"
                }
            };
            await middleware.moveReqDatabaseUserEmailToReqUserEmail(req, res, nextFunc);
            assert.ok(!req.databaseUser.email, 'Problem in email');
            assert.ok(req.user.email, 'Problem in email');
        });
    });

    describe('test function loginUserUsingReqIncomingUserReqDatabaseUser', () => {
        it('bad hash should fail', async () => {
            req = {
                incomingUser: {
                    email: "validUsernamePassTest@gmail.com",
                    password: "secre*77newpass"
                },
                databaseUser: {
                    email: "validUsernamePassTest@gmail.com",
                    user_id: 123456788,
                    hash: "somethisnf827273shseoe"
                }
            };
            await middleware.loginUserUsingReqIncomingUserReqDatabaseUser(req, res, nextFunc);
            assert.ok(!req.user, 'Should have failed');
        });

        it('bad hash should pass', async () => {
            req = {
                incomingUser: {
                    email: "validUsernamePassTest@gmail.com",
                    password: "secre*77newpass"
                },
                databaseUser: {
                    email: "validUsernamePassTest@gmail.com",
                    user_id: 123456788,
                }
            };
            req.databaseUser.hash = hash.createPasswordHashStoreString(req.incomingUser.password, hash.createRandomSalt());
            await middleware.loginUserUsingReqIncomingUserReqDatabaseUser(req, res, nextFunc);
            assert.ok(req.user, 'Should login');
        });
    });

    describe('test parseJwtFromUrlParamJwtAndAttachToReq', () => {
        it('good jwt should pass', async () => {
            req = {
                params: {
                    jwt: 'eyJhbGciOiJzaGE1MTIiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoxMjM0NTY3ODksInRpbWUiOjE2MTA5MDU4ODE2NDB9.BxfZhC8VtFqdMFJlPizianLpxS4D5UIyKphylTaEgJECF2kfLcIEgiOvvhqc7NmiLFQnFpqXvRShCVinSWe7vA',
                },
            };
            await middleware.parseJwtFromUrlParamJwtAndAttachToReq(req, res, nextFunc);
            assert.ok(req.recoveryJwtToken.length > 100, 'jwt too small');
        });
    });

    describe('test verifyIncomingJwtTokenSignature', () => {
        it('good jwt should pass', async () => {
            req = {
                recoveryJwtToken: 'eyJhbGciOiJzaGE1MTIiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoxMjM0NTY3ODksInRpbWUiOjE2MTA5MDU4ODE2NDB9.BxfZhC8VtFqdMFJlPizianLpxS4D5UIyKphylTaEgJECF2kfLcIEgiOvvhqc7NmiLFQnFpqXvRShCVinSWe7vA',
            };
            await middleware.verifyIncomingJwtTokenSignature(req, res, nextFunc);
            assert.ok(!!req.signatureVerifiedJwtToken, 'jwt too small');
        });
    });

    describe('test verifyIncomingJwtTokenSignature', () => {
        it('good jwt should pass', async () => {
            req = {
                signatureVerifiedJwtToken: 'eyJhbGciOiJzaGE1MTIiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoxMjM0NTY3ODksInRpbWUiOjE2MTA5MDU4ODE2NDB9.BxfZhC8VtFqdMFJlPizianLpxS4D5UIyKphylTaEgJECF2kfLcIEgiOvvhqc7NmiLFQnFpqXvRShCVinSWe7vA',
            };
            await middleware.readReqSignatureVerifiedJwtTokenAttachToReqUser(req, res, nextFunc);
            assert.deepStrictEqual(req.user.payload.user_id, 123456789, 'jwt too small');
        });
    });

});