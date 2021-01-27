const Middleware = (util, commonUtil, validate) => {

    const initializeAllVariablesInReq = (req, res, next) => {
        req.error = null;
        req.user = null;
        req.incomingUser = null;
        req.databaseUser = null;
        req.jwtToken = null;
        req.incomingJwtToken = null;
        req.signatureVerifiedJwtToken = null;
        req.jwtPayload = null;
        req.jwtHeader = null;
        req.jwtToken = null;
        next();
    };

    /**
     * Validates email and attaches to req.incomingUser.email
     * @param req
     * @param res
     * @param next
     */
    const validateEmailInReqBodyEmail = (req, res, next) => {
        if ((!!req.body) && (!!req.body.email) && (validate.isEmail(req.body.email))) {
            req.incomingUser = {
                ...req.incomingUser, email: req.body.email
            };
            req.body.email = null;
            next();
        } else {
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
    const validatePasswordInReqBodyPassword = (req, res, next) => {
        if ((!!req.body) && (!!req.body.password) &&
            validate.isStringOfPassword(req.body.password)) {
            req.incomingUser = {
                ...req.incomingUser, password: req.body.password
            };
            req.body.password = null;
            next();
        } else {
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
    const createIncomingUserHash = (req, res, next) => {
        if ((!!req.incomingUser) && (!!req.incomingUser.password)) {
            const hash = util.createPasswordHashStoreString(req.incomingUser.password, util.createRandomSalt());
            req.incomingUser = {...req.incomingUser, hash}
            req.incomingUser.password = null;
            next();
        } else {
            req.error = {place: "createIncomingUserHash"};
            next('route');
        }
    }

    /**
     * Create hash using salt stored in database
     * @param req
     * @param res
     * @param next
     */
    const createIncomingUserHashForLogin = (req, res, next) => {
        if ((!!req.incomingUser) &&
            (!!req.incomingUser.password) &&
            (!!req.databaseUser) &&
            (!!req.databaseUser.hash)) {
            const decomposedPassword = commonUtil.decomposePasswordHashStoreString(req.databaseUser.hash);
            const hash = util.createPasswordHashStoreString(req.incomingUser.password, decomposedPassword.salt);
            req.incomingUser = {...req.incomingUser, hash}
            req.incomingUser.password = null;
            next();
        } else {
            req.error = {place: "createIncomingUserHashForLogin"};
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
    const createJwtHeaderPayloadForJwtFromReqUserSHA512 = (req, res, next) => {
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
            req.error = {place: "createJwtHeaderPayloadForJwtFromReqUserSHA512"};
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
    const createJwtTokenSHA512 = (req, res, next) => {
        if (req.jwtHeader || req.jwtPayload) {
            req.jwtToken = util.jwtCreateSHA512(req.jwtHeader, req.jwtPayload);
            req.jwtHeader = null;
            req.jwtPayload = null;
            next();
        } else {
            req.error = {place: "createJwtTokenSHA512"};
            next('route');
        }
    }

    /**
     * Sends jwt to the user in reply
     * @param req
     * @param res
     * @param next
     */
    const sendJwtInReply = (req, res, next) => {
        if ((!!req.jwtToken)) {
            res.json({jwt: req.jwtToken});
        } else {
            req.error = {place: "sendJwtInReply"};
            next('route');
        }
    }

    /**
     * Move req.databaseUser.user_id to req.user.user_id
     * @param req
     * @param res
     * @param next
     */
    const moveReqDatabaseUserIdToReqUserId = (req, res, next) => {
        if ((!!req.databaseUser) && (!!req.databaseUser.user_id)) {
            req.user = {
                ...req.user,
                user_id: req.databaseUser.user_id
            };
            req.databaseUser = {...req.databaseUser, user_id: null};
            next();
        } else {
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
    const moveReqDatabaseUserEmailToReqUserEmail = (req, res, next) => {
        if ((!!req.databaseUser) && (!!req.databaseUser.email)) {
            req.user = {
                ...req.user,
                email: req.databaseUser.email
            };
            req.databaseUser = {...req.databaseUser, email: null};
            next();
        } else {
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
    const loginUserUsingReqIncomingUserReqDatabaseUser = (req, res, next) => {
        if ((!!req.incomingUser) &&
            (!!req.databaseUser) &&
            (!!req.incomingUser.hash) &&
            (!!req.incomingUser.email) &&
            (!!req.databaseUser.hash) &&
            (!!req.databaseUser.email) &&
            (!!req.databaseUser.user_id) &&
            (req.incomingUser.hash === req.databaseUser.hash) &&
            (req.incomingUser.email === req.databaseUser.email)) {
            req.user = {
                user_id: req.databaseUser.user_id,
                email: req.databaseUser.email
            };
            req.incomingUser = {...req.incomingUser, hash: null, email: null};
            req.databaseUser = {...req.databaseUser, hash: null, email: null, user_id: null};
            next();
        } else {
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
    const parseJwtFromUrlParamJwtAndAttachToReq = (req, res, next) => {
        if (!!req.params && !!req.params.jwt &&
            (validate.validateStringForCharactersPermittedInJwt(req.params.jwt))) {
            req.incomingJwtToken = req.params.jwt;
            req.params.jwt = null;
            next();
        } else {
            next();
        }
    }

    /**
     * Jwt comes in the body.jwt
     * @param req
     * @param res
     * @param next
     */
    const parseJwtFromBodyAndAttachToReq = (req, res, next) => {
        if (!!req.body && !!req.body.jwt &&
            (validate.validateStringForCharactersPermittedInJwt(req.body.jwt))) {
            req.incomingJwtToken = req.body.jwt;
            req.body.jwt = null;
            next();
        } else {
            next();
        }
    };

    const parseJwtFromAuthenticationHeaderAndAttachToReq = (req, res, next) => {
    };



    /**
     * verify jwt signatures are correct and attach to req.jwtToken
     * @param req
     * @param res
     * @param next
     */
    const verifyIncomingJwtTokenSignature = (req, res, next) => {
        if (!!req.incomingJwtToken && util.jwtIsSignatureValid(req.incomingJwtToken)) {
            req.signatureVerifiedJwtToken = req.incomingJwtToken;
            req.incomingJwtToken = null;
            next();
        } else {
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
    const readReqSignatureVerifiedJwtTokenAttachToReqUser = (req, res, next) => {
        if ((!!req.signatureVerifiedJwtToken)) {
            req.user = util.jwtRead(req.signatureVerifiedJwtToken);
            req.signatureVerifiedJwtToken = null;
            next();
        } else {
            req.error = {place: "readReqSignatureVerifiedJwtTokenAttachToReqUser"};
            next('route');
        }
    };

    /**
     * Send password updated success message
     * @param req
     * @param res
     * @param next
     */
    const sendPasswordUpdatedReply = (req, res, next) => {
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
    const emailLinkForPasswordRecovery = (req, res, next) => {
            res.json({
                message: "Please check your mail",
                jwt: req.jwtToken // Should go in the email
            })
        }

    return {
        parseJwtFromBodyAndAttachToReq,
        initializeAllVariablesInReq,
        validateEmailInReqBodyEmail,
        validatePasswordInReqBodyPassword,
        createIncomingUserHash,
        createIncomingUserHashForLogin,
        createJwtTokenSHA512,
        createJwtHeaderPayloadForJwtFromReqUserSHA512,
        moveReqDatabaseUserIdToReqUserId,
        moveReqDatabaseUserEmailToReqUserEmail,
        loginUserUsingReqIncomingUserReqDatabaseUser,
        parseJwtFromUrlParamJwtAndAttachToReq,
        verifyIncomingJwtTokenSignature,
        readReqSignatureVerifiedJwtTokenAttachToReqUser,
        sendJwtInReply,
        sendPasswordUpdatedReply,
        emailLinkForPasswordRecovery
    };
}

module.exports = Middleware;