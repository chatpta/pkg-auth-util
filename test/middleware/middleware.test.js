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
// const hash = new index.Hash(defaultValues);
// const validata = new index.Validate();


describe('Middleware tests', () => {
    let nextFunc = function (req, res) {
    };
    let res = {
        json: (obj) => res.body = obj
    };
    let req;

    // incomingUser: {
    //     email: "validUsernamePassTest@gmail.com",
    //     password: "secre*77pass"
    // }
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

    // it('validateEmail', async () => {
    //     req = {
    //         body: {
    //             email: "validUsernamePassTest@gmail.com"
    //         }
    //     };
    //     await middleware.validateEmail(req, res, nextFunc);
    //     assert.ok(!!req.incomingUser,
    //         'Problem in validateEmail');
    // });
    //
    // it('validatePassword', async () => {
    //     req = {
    //         body: {
    //             password: "secre*77newpass"
    //         }
    //     };
    //     await middleware.validatePassword(req, res, nextFunc);
    //     assert.ok(!!req.incomingUser.password,
    //         'Problem in validatePassword');
    // });
    //
    // it('validatePassword should fail', async () => {
    //     req = {
    //         body: {
    //             password: "bad pass"
    //         }
    //     };
    //     await middleware.validatePassword(req, res, nextFunc);
    //     assert.ok(!req.incomingUser,
    //         'Problem in validatePassword');
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