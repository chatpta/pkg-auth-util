const assert = require('assert');
const index = require('../../index');

const util = new index.JwtReader();
const commonUtil = index.CommonUtil;
const validate = index.Validate;
const auth = index.Middleware(util,commonUtil, validate);

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

    describe('test function createHeaderPayloadForJwtFromReqUserSHA512', () => {
        it('create header', (done) => {
            req.user = {user_id: 123456789};
            auth.createJwtHeaderPayloadForJwtFromReqUserSHA512(req, res, nextFunc);
            assert.ok(!!req.jwtPayload.user_id,
                'user_id not there');
            done();
        });
    });

    describe('test function createJwtTokenSHA512', () => {
        it('create jwt token', async () => {
            req.user = {user_id: 123456789};
            await auth.createJwtHeaderPayloadForJwtFromReqUserSHA512(req, res, nextFunc);
            await auth.createJwtTokenSHA512(req, req, nextFunc);
            assert.ok(!req.jwtPayload, 'payload is not consumed');
            assert.ok(req.jwtToken.length > 100, 'jwtToken not created');
        });
    });

    describe('test function sendJwtInReply', () => {
        it('sends jwt token', async () => {
            req.user = {user_id: 123456789};
            await auth.createJwtHeaderPayloadForJwtFromReqUserSHA512(req, res, nextFunc);
            await auth.createJwtTokenSHA512(req, req, nextFunc);
            await auth.sendJwtInReply(req, res, nextFunc);
            assert.ok((res.body.jwt.length > 100), 'not returning jwt');
        });
    });

    describe('test function validateEmailInReqBodyEmail', () => {
        it('valid Email', (done) => {
            req = {
                body: {
                    email: "validUsernamePassTest@gmail.com"
                }
            };
            auth.validateEmailInReqBodyEmail(req, res, nextFunc);
            assert.ok(req.incomingUser.email.length > 5, 'Problem in valid Email');
            done();
        });

        it('not valid Email', () => {
            req = {
                body: {
                    email: "validUsernamePassTestgmail.com"
                }
            };
            auth.validateEmailInReqBodyEmail(req, res, nextFunc);
            assert.deepStrictEqual(req.error.place, 'validateEmailInReqBodyEmail');
        });
    });

    describe('test function validatePasswordInReqBodyPassword', () => {
        it('validatePassword', () => {
            req = {
                body: {
                    password: "secre*77newpass"
                }
            };
            auth.validatePasswordInReqBodyPassword(req, res, nextFunc);
            assert.ok(req.incomingUser.password.length > 5, 'Problem in validatePassword');
        });

        it('validatePassword should fail', () => {
            req = {
                body: {
                    password: "bad pass"
                }
            };
            auth.validatePasswordInReqBodyPassword(req, res, nextFunc);
            assert.deepStrictEqual(req.error.place, "validatePasswordInReqBodyPassword");
        });
    });

    describe('test function createIncomingUserHash', () => {
        it('create hash', () => {
            req = {
                incomingUser: {
                    password: "secre*77newpass"
                }
            };
            auth.createIncomingUserHash(req, res, nextFunc);
            assert.ok(req.incomingUser.hash.length > 100, 'Problem in hash creation');
        });

    });

    describe('test function email password move to req.user from req.databaseUser', () => {
        it('move user_id', () => {
            req = {
                databaseUser: {
                    email: "validUsernamePassTest@gmail.com",
                    user_id: 123456788,
                    hash: "somethisnf827273shseoe"
                }
            };
            auth.moveReqDatabaseUserIdToReqUserId(req, res, nextFunc);
            assert.ok(!req.databaseUser.user_id, 'Problem in user_id');
            assert.ok(req.user.user_id, 'Problem in user_id');
        });

        it('move email', () => {
            req = {
                databaseUser: {
                    email: "validUsernamePassTest@gmail.com",
                    user_id: 123456788,
                    hash: "somethisnf827273shseoe"
                }
            };
            auth.moveReqDatabaseUserEmailToReqUserEmail(req, res, nextFunc);
            assert.ok(!req.databaseUser.email, 'Problem in email');
            assert.ok(req.user.email, 'Problem in email');
        });
    });

    describe('test function loginUserUsingReqIncomingUserReqDatabaseUser', () => {
        it('bad hash should fail', () => {
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
            auth.loginUserUsingReqIncomingUserReqDatabaseUser(req, res, nextFunc);
            assert.ok(!req.user, 'Should have failed');
        });

        it('good hash should pass', () => {
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
            req.databaseUser.hash = util.createPasswordHashStoreString(req.incomingUser.password, util.createRandomSalt());
            auth.createIncomingUserHashForLogin(req, res, nextFunc);
            auth.loginUserUsingReqIncomingUserReqDatabaseUser(req, res, nextFunc);
            assert.ok(req.user, 'Should login');
        });
    });

    describe('test parseJwtFromUrlParamJwtAndAttachToReq', () => {
        it('good jwt should pass', () => {
            req = {
                params: {
                    jwt: 'eyJhbGciOiJzaGE1MTIiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoxMjM0NTY3ODksInRpbWUiOjE2MTA5MDU4ODE2NDB9.BxfZhC8VtFqdMFJlPizianLpxS4D5UIyKphylTaEgJECF2kfLcIEgiOvvhqc7NmiLFQnFpqXvRShCVinSWe7vA',
                },
            };
            auth.parseJwtFromUrlParamJwtAndAttachToReq(req, res, nextFunc);
            assert.ok(req.incomingJwtToken.length > 100, 'jwt too small');
        });
    });

    describe('test verifyIncomingJwtTokenSignature', () => {
        it('good jwt should pass', () => {
            req = {
                incomingJwtToken: 'eyJhbGciOiJzaGE1MTIiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoxMjM0NTY3ODksInRpbWUiOjE2MTA5MDU4ODE2NDB9.BxfZhC8VtFqdMFJlPizianLpxS4D5UIyKphylTaEgJECF2kfLcIEgiOvvhqc7NmiLFQnFpqXvRShCVinSWe7vA',
            };
            auth.verifyIncomingJwtTokenSignature(req, res, nextFunc);
            assert.ok(!!req.signatureVerifiedJwtToken, 'jwt too small');
        });
    });

    describe('test verifyIncomingJwtTokenSignature', () => {
        it('good jwt should pass', () => {
            req = {
                signatureVerifiedJwtToken: 'eyJhbGciOiJzaGE1MTIiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoxMjM0NTY3ODksInRpbWUiOjE2MTA5MDU4ODE2NDB9.BxfZhC8VtFqdMFJlPizianLpxS4D5UIyKphylTaEgJECF2kfLcIEgiOvvhqc7NmiLFQnFpqXvRShCVinSWe7vA',
            };
            auth.readReqSignatureVerifiedJwtTokenAttachToReqUser(req, res, nextFunc);
            assert.deepStrictEqual(req.user.payload.user_id, 123456789, 'jwt too small');
        });
    });

    describe('test function sendPasswordUpdatedReply', () => {
        it('sends update reply', () => {
            req.user = {updated: true};
            auth.sendPasswordUpdatedReply(req, res, nextFunc);
            assert.deepStrictEqual(res.body.message, 'update successful',
                'not returning message');
        });
    });

});