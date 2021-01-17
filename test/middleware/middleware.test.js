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
            await middleware.createHeaderPayloadForJwtFromReqUserSHA512(req, res, nextFunc);
            assert.ok(!!req.payload.user_id,
                'user_id not there');
        });
    });

    describe('test function createJwtTokenSHA512', () => {
        it('create jwt token', async () => {
            req.user = {user_id: 123456789};
            await middleware.createHeaderPayloadForJwtFromReqUserSHA512(req, res, nextFunc);
            await middleware.createJwtTokenSHA512(req, req, nextFunc);
            assert.ok(!req.payload, 'payload is not consumed');
            assert.ok(req.jwtToken.length > 100, 'jwtToken not created');
        });
    });

    describe('test function sendJwtInReply', () => {
        it('sends jwt token', async () => {
            req.user = {user_id: 123456789};
            await middleware.createHeaderPayloadForJwtFromReqUserSHA512(req, res, nextFunc);
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

    describe('test function createJwtHeaderPayloadFromReqUser', () => {
        it('create req.jwtHeader req.jwtPayload', async () => {
            req = {
                user: {
                    email: "validUsernamePassTest@gmail.com",
                    user_id: 123456788,
                }
            };
            await middleware.createJwtHeaderPayloadFromReqUser(req, res, nextFunc);
            assert.deepStrictEqual(req.jwtPayload.user_id, 123456788,
                'Should have passed');
        });
    });

    //
    // it('create jwt test', async () => {
    //     await userController.findUserAndAttachToRequest(req, res, nextFunc);
    //     await middleware.validateUserForForgotPassword(req, res, nextFunc);
    //     await middleware.createHeaderPayloadForJwt(req, res, nextFunc);
    //     await authMiddleware.createJwtToken(req, res, nextFunc);
    //     assert.ok(req.jwtToken.length > 50,
    //         'Jwt is smaller than 50 characters');
    // });
    //
    // it('send jwt test', async () => {
    //     await userController.findUserAndAttachToRequest(req, res, nextFunc);
    //     await middleware.createHeaderPayloadForJwt(req, res, nextFunc);
    //     await authMiddleware.createJwtToken(req, res, nextFunc);
    //     await middleware.sendJwtInReply(req, res, nextFunc);
    //     assert.ok((typeof res.json === "function"),
    //         'not returning jwt');
    // });
    //
    // it('simulate login', async () => {
    //     req = {
    //         body: {
    //             email: "validUsernamePassTest@gmail.com",
    //             password: "secre*77pass"
    //         }
    //     };
    //     await authMiddleware.validateUsernamePassword(req, res, nextFunc);
    //     await userController.findUserAndAttachToRequest(req, res, nextFunc);
    //     await authMiddleware.verifyUserForLogin(req, res, nextFunc);
    //     await middleware.createHeaderPayloadForJwt(req, res, nextFunc);
    //     await authMiddleware.createJwtToken(req, res, nextFunc);
    //     await middleware.sendJwtInReply(req, res, nextFunc);
    //     assert.ok((typeof res.json === "function"),
    //         'not returning jwt');
    // });


    // it('simulate forget', async () => {
    //     req = {
    //         body: {
    //             email: "validUsernamePassTest@gmail.com"
    //         }
    //     };
    //     await middleware.validateEmail(req, res, nextFunc);
    //     await userController.findUserAndAttachToRequest(req, res, nextFunc);
    //     await middleware.validateUserForForgotPassword(req, res, nextFunc);
    //     await middleware.createHeaderPayloadForJwt(req, res, nextFunc);
    //     await authMiddleware.createJwtToken(req, res, nextFunc);
    //     await middleware.emailLinkForPasswordRecovery(req, res, nextFunc);
    //     assert.ok((typeof res.json === "function"),
    //         'not returning jwt');
    // });
    //
    // it('simulate reset/:jwt', async () => {
    //     req = {
    //         body: {
    //             email: "validUsernamePassTest@gmail.com"
    //         }
    //     };
    //     await middleware.validateEmail(req, res, nextFunc);
    //     await userController.findUserAndAttachToRequest(req, res, nextFunc);
    //     await middleware.validateUserForForgotPassword(req, res, nextFunc);
    //     await middleware.createHeaderPayloadForJwt(req, res, nextFunc);
    //     await authMiddleware.createJwtToken(req, res, nextFunc);
    //     // We get new jwt for recovery
    //     req = {
    //         params: {
    //             jwt: req.jwtToken
    //         },
    //         body: {
    //             password: "secre*77newpass"
    //         }
    //     };
    //     await middleware.parseJwtFromUrlAndAttachToReq(req, res, nextFunc);
    //     await middleware.verifyIncomingJwtTokenSignature(req, res, nextFunc);
    //     await authMiddleware.parseJwtToken(req, res, nextFunc);
    //     await middleware.validatePassword(req, res, nextFunc);
    //     await userController.updateUserHash(req, res, nextFunc);
    //     await middleware.sendPasswordUpdatedReply(req, res, nextFunc);
    //     assert.ok((typeof res.json === "function"),
    //         'not returning jwt');
    // });
    //

});