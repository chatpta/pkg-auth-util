const JwtCreator = require('../util/jwtCreator');
const validate = require('../validate/validate');
const Hash = require('../util/hash');


const jwtCreator = new JwtCreator();
const hash = new Hash();


class Middleware {

    /**
     * Validates email and attaches to req.incomingUser.email
     * @param req
     * @param res
     * @param next
     */
    validateEmailInReqBodyEmail(req, res, next) {
        if ((!!req.body) && (!!req.body.email) && (validate.isEmail(req.body.email))) {
            req.incomingUser = {
                ...req.incomingUser, email: req.body.email
            };
            req.body.email = null;
            next();
        } else {
            req.incomingUser = {
                ...req.incomingUser, email: null
            };
            req.error = {place: "validateEmailInReqBodyEmail"};
            next('route');
        }
    }

    /**
     * Validates req.body.password and attaches to req.incomingUser.password
     * consumes req.body.password
     * @param req
     * @param res
     * @param next
     */
    validatePasswordInReqBodyPassword(req, res, next) {
        if ((!!req.body) && (!!req.body.password) &&
            validate.isStringOfPassword(req.body.password)) {
            req.incomingUser = {
                ...req.incomingUser, password: req.body.password
            };
            req.body.password = null;
            next();
        } else {
            req.incomingUser = {
                ...req.incomingUser, password: null
            };
            req.error = {place: "validatePasswordInReqBodyPassword"};
            next('route');
        }
    }

    /**
     * Creates req.header and req.payload object from the req.user
     * @param req
     * @param res
     * @param next
     * @returns {Promise<void>}
     */
    createJwtHeaderPayloadForJwtFromReqUserSHA512(req, res, next) {
        if ((!!req.user) &&
            (!!req.user.user_id)) {
            req.jwtHeader = {
                "alg": "sha512",
                "typ": "JWT"
            };
            req.jwtPayload = {
                "user_id": req.user.user_id,
                "time": Date.now(),
            };
            req.user = {...req.user, user_id: null};
            next();
        } else {
            req.jwtHeader = null;
            req.jwtPayload = null;
            req.error = {place: "createJwtHeaderPayloadFromReqUser"};
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
        if (!req.jwtHeader || !req.jwtPayload) {
            req.jwtToken = null;
            next('route');
        } else {
            req.jwtToken = jwtCreator.jwtCreateSHA512(req.jwtHeader, req.jwtPayload);
            req.jwtHeader = null;
            req.jwtPayload = null;
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

    /**
     * Move req.databaseUser.user_id to req.user.user_id
     * @param req
     * @param res
     * @param next
     */
    moveReqDatabaseUserIdToReqUserId(req, res, next) {
        if ((!!req.databaseUser) && (!!req.databaseUser.user_id)) {
            req.user = {
                ...req.user,
                user_id: req.databaseUser.user_id
            };
            req.databaseUser = {...req.databaseUser, user_id: null};
            next();
        } else {
            req.user = {...req.user, user_id: null};
            req.error = {place: "moveReqDatabaseUserIdToReqUserId"};
            next('route');
        }
    }

    /**
     * Move req.databaseUser.email to req.user.email
     * @param req
     * @param res
     * @param next
     */
    moveReqDatabaseUserEmailToReqUserEmail(req, res, next) {
        if ((!!req.databaseUser) && (!!req.databaseUser.email)) {
            req.user = {
                ...req.user,
                email: req.databaseUser.email
            };
            req.databaseUser = {...req.databaseUser, email: null};
            next();
        } else {
            req.user = {...req.user, email: null}
            req.error = {place: "moveReqDatabaseUserEmailToReqUserEmail"};
            next('route');
        }
    }


    /**
     * If user logged in req.user contains user_id and email user is null otherwise
     * @param req
     * @param res
     * @param next
     */
    loginUserUsingReqIncomingUserReqDatabaseUser(req, res, next) {
        if ((!!req.incomingUser) &&
            (!!req.databaseUser) &&
            (!!req.incomingUser.password) &&
            (!!req.incomingUser.email) &&
            (!!req.databaseUser.hash) &&
            (!!req.databaseUser.email) &&
            (!!req.databaseUser.user_id) &&
            hash.verifyPasswordHash(req.incomingUser.password, req.databaseUser.hash) &&
            req.incomingUser.email === req.databaseUser.email) {
            req.user = {
                user_id: req.databaseUser.user_id,
                email: req.databaseUser.email
            };
            req.incomingUser = {...req.incomingUser, password: null, email: null};
            req.databaseUser = {...req.databaseUser, hash: null, email: null, user_id: null};
            next();
        } else {
            req.user = null;
            req.error = {place: "loginUserUsingReqIncomingUserReqDatabaseUser"};
            next('route');
        }
    }



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