const JwtCreator = require('../util/jwtCreator');


const jwtCreator = new JwtCreator();

class Middleware {

    /**
     * Puts req.user.user_id in req.payload.user_id
     * Consumes req.user
     * sets req.user to null
     * @param req
     * @param res
     * @param next
     * @returns {Promise<void>}
     */
    createHeaderPayloadForJwtFromReqUserSHA512(req, res, next) {
        if ((!!req.user) &&
            (!!req.user.user_id)) {
            req.header = {
                "alg": "sha512",
                "typ": "JWT"
            };
            req.payload = {
                "user_id": req.user.user_id,
                "time": Date.now(),
            };
            req.user = null;
            next();
        } else {
            req.header = null;
            req.payload = null;
            req.error = {place: "createHeaderPayloadForJwtFromReqUserSHA512"};
            next('route');
        }
    }


    /**
     * Creates a jwt token and attach to req.jwtToken
     * consumes req.header and req.payload
     * @param req
     * @param res
     * @param next
     */
    createJwtTokenSHA512(req, res, next) {
        if (!req.header || !req.payload) {
            req.jwtToken = null;
            next('route');
        } else {
            req.jwtToken = jwtCreator.jwtCreateSHA512(req.header, req.payload);
            req.header = null;
            req.payload = null;
            next();
        }
    }


    /**
     * Sends jwt to the user in reply
     * @param req
     * @param res
     * @param next
     */
    sendJwtInReply(req, res, next) {
        if ((!!req.jwtToken)) {
            res.json({jwt: req.jwtToken});
        } else {
            req.jwtToken = null;
            next('route');
        }
    }

    // /**
    //  * Check if user is there
    //  * User has been found just need to put the user in user.databaseUser
    //  * @param req
    //  * @param res
    //  * @param next
    //  */
    // validateUserForForgotPassword(req, res, next) {
    //     if ((!!req.databaseUser) && (!!req.databaseUser.user_id)) {
    //         req.user = {
    //             user_id: req.databaseUser.user_id,
    //             email: req.databaseUser.email
    //         };
    //         req.incomingUser = null;
    //         req.databaseUser = null;
    //         next();
    //     } else {
    //         req.user = null;
    //         req.databaseUser = null;
    //         req.error = {place: "validateUserForForgotPassword"};
    //         next();
    //     }
    // }
    //
    // /**
    //  * Validates email and attaches to req.incomingUser.email
    //  * @param req
    //  * @param res
    //  * @param next
    //  */
    // validateEmail(req, res, next) {
    //     if ((!!req.body) && (!!req.body.email) &&!validate.isEmail(req.body.email)) {
    //         req.body.email = null;
    //         req.error = {place: "validateEmail"};
    //         next();
    //     } else {
    //         req.incomingUser = {
    //             email: req.body.email
    //         };
    //         req.body.email = null;
    //         next();
    //     }
    // }

    // /**
    //  * Validates and parses jwt from the params
    //  * @param req
    //  * @param res
    //  * @param next
    //  */
    // parseJwtFromUrlAndAttachToReq(req, res, next) {
    //     if (!!req.params && !!req.params.jwt &&
    //         !localValidate.validateStringForCharactersPermittedInJwt(req.params.jwt)) {
    //         next('route');
    //     } else {
    //         req.recoveryJwtToken = req.params.jwt;
    //         req.params.jwt = null;
    //         next();
    //     }
    // }
    //
    // /**
    //  * verify jwt signatures are correct and attach to req.jwtToken
    //  * @param req
    //  * @param res
    //  * @param next
    //  */
    // verifyIncomingJwtTokenSignature(req, res, next) {
    //     if (!!req.recoveryJwtToken && authUtil.verifySignatureJWT(req.recoveryJwtToken)) {
    //         req.jwtToken = req.recoveryJwtToken;
    //         req.recoveryJwtToken = null;
    //         next();
    //     } else {
    //         req.recoveryJwtToken = null;
    //         req.error = {place: "verifyIncomingJwtTokenSignature"};
    //         next();
    //     }
    // }

    // /**
    //  * Validates email and attaches to req.incomingUser.email
    //  * @param req
    //  * @param res
    //  * @param next
    //  */
    // validatePassword(req, res, next) {
    //     if ((!!req.body) && (!!req.body.password) &&
    //         validate.isStringOfPassword(req.body.password)) {
    //         req.incomingUser = {
    //             password: req.body.password
    //         };
    //         req.body.password = null;
    //         next();
    //     } else {
    //         req.error = {place: "validatePassword"};
    //         next('route');
    //     }
    // }
    //
    // /**
    //  * Send password updated success message
    //  * @param req
    //  * @param res
    //  * @param next
    //  */
    // sendPasswordUpdatedReply(req, res, next){
    //     if ((!!req.user) && (!!req.user.updated)) {
    //         res.json({message: "update successful"})
    //         next();
    //     } else {
    //         req.error = {place: "sendPasswordUpdatedReply"};
    //         next('route');
    //     }
    // }
    //
    // /**
    //  * Sends email for recovery
    //  * @param req
    //  * @param res
    //  * @param next
    //  */
    // //Todo:: email sending to be implemented
    // emailLinkForPasswordRecovery(req, res, next) {
    //     res.json({
    //         message: "Please check your mail",
    //         jwt: req.jwtToken // Should go in the email
    //     })
    // }
    //
    //
    // /**
    //  * This is analogus to verifyUserForLogin function, it validates that user can be sent jwt
    //  * @param req
    //  * @param res
    //  * @param next
    //  */
    // validateReceivedJwtForRecovery(req, res, next) {
    //     //todo:: should check for the email exist
    //     req.user = {
    //         user_id: req.databaseUser.user_id,
    //         email: req.databaseUser.email
    //     };
    //     req.databaseUser = null;
    //     next();
    // }
    //
    // /**
    //  * This is analogus to verifyUserForLogin function, it validates that user can be sent jwt
    //  * @param req
    //  * @param res
    //  * @param next
    //  */
    // validateUserForPasswordRecovery(req, res, next) {
    //     //todo:: should check for the signature
    //     req.user = {
    //         user_id: req.databaseUser.user_id,
    //         email: req.databaseUser.email
    //     };
    //     req.databaseUser = null;
    //     next();
    // }
}

module.exports = Middleware;