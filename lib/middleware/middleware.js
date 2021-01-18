const JwtReader = require('../util/jwtReader');
const validate = require('../validate/validate');


class Middleware extends JwtReader {
    constructor(defaultValues) {
        super(defaultValues);
    }


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
     * create hash and attach to req.incomingUser.hash
     * @param req
     * @param res
     * @param next
     * @returns {Promise<void>}
     */
    async createIncomingUserHash(req, res, next) {
        if ((!!req.incomingUser) && (!!req.incomingUser.password)) {
            const hash = await this.createPasswordHashStoreString(req.incomingUser.password, this.createRandomSalt());
            req.incomingUser = {...req.incomingUser, hash}
            req.incomingUser.password = null;
            next();
        } else {
            req.incomingUser = {
                ...req.incomingUser, hash: null
            };
            req.error = {place: "createIncomingUserHash"};
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
            req.jwtToken = this.jwtCreateSHA512(req.jwtHeader, req.jwtPayload);
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
    async loginUserUsingReqIncomingUserReqDatabaseUser(req, res, next) {
        if ((!!req.incomingUser) &&
            (!!req.databaseUser) &&
            (!!req.incomingUser.password) &&
            (!!req.incomingUser.email) &&
            (!!req.databaseUser.hash) &&
            (!!req.databaseUser.email) &&
            (!!req.databaseUser.user_id) &&
            await this.verifyPasswordHash(req.incomingUser.password, req.databaseUser.hash) &&
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


    /**
     * Validates and parses jwt from the params and attach to req.recoveryJwtToken
     * @param req
     * @param res
     * @param next
     */
    parseJwtFromUrlParamJwtAndAttachToReq(req, res, next) {
        if (!!req.params && !!req.params.jwt &&
            (!validate.validateStringForCharactersPermittedInJwt(req.params.jwt))) {
            next('route');
        } else {
            req.recoveryJwtToken = req.params.jwt;
            req.params.jwt = null;
            next();
        }
    }


    /**
     * verify jwt signatures are correct and attach to req.jwtToken
     * @param req
     * @param res
     * @param next
     */
    verifyIncomingJwtTokenSignature(req, res, next) {
        if (!!req.recoveryJwtToken && this.jwtIsSignatureValid(req.recoveryJwtToken)) {
            req.signatureVerifiedJwtToken = req.recoveryJwtToken;
            req.recoveryJwtToken = null;
            next();
        } else {
            req.signatureVerifiedJwtToken = null;
            req.recoveryJwtToken = null;
            req.error = {place: "verifyIncomingJwtTokenSignature"};
            next('route');
        }
    }


    /**
     * Parses jwt token from Authorization header and attach to req.user
     * @param req
     * @param res
     * @param next
     * @returns {Promise<void>}
     */
    async readReqSignatureVerifiedJwtTokenAttachToReqUser(req, res, next) {
        if ((!!req.signatureVerifiedJwtToken)) {
            req.user = this.jwtRead(req.signatureVerifiedJwtToken);
            req.signatureVerifiedJwtToken = null;
            next();
        } else {
            req.user = null;
            next('route');
        }
    };

    /**
     * Send password updated success message
     * @param req
     * @param res
     * @param next
     */
    sendPasswordUpdatedReply(req, res, next) {
        if ((!!req.user) && (!!req.user.updated)) {
            req.user = null;
            res.json({message: "update successful"})
            next();
        } else {
            req.error = {place: "sendPasswordUpdatedReply"};
            next('route');
        }
    }

    /**
     * Sends email for recovery
     * @param req
     * @param res
     * @param next
     */
    //Todo:: email sending to be implemented
    emailLinkForPasswordRecovery(req, res, next) {
        res.json({
            message: "Please check your mail",
            jwt: req.jwtToken // Should go in the email
        })
    }
}

module.exports = Middleware;