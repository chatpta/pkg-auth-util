const jwtLib = require( './lib/jwtLib' )
const pwdUtilAuth = require( './lib/pwdUtilAuth' );
const jwtUtilAuth = require( './lib/jwtUtilAuth' );

module.exports = {
    jwtUtilAuth: {
        createSignedJwtFromObject: jwtUtilAuth.createSignedJwtFromObject,
        verifyJwtSignature: jwtUtilAuth.verifyJwtSignature,
        getHeaderPayloadFromJwt: jwtUtilAuth.getHeaderPayloadFromJwt
    },

    pwdUtilAuth: {
        createPasswordHashWithRandomSalt: pwdUtilAuth.createPasswordHashWithRandomSalt,
        createPasswordHashBasedOnSavedAlgorithmSalt: pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt
    },

    stringUtilAuth: require( './lib/stringUtilAuth' ),
    jwtAsyncMiddleware: require( './lib/jwtAsyncMiddleware' ),

    jwtLib: {
        jwtClientId: jwtLib.jwtClientId,
        isJwtExpired: jwtLib.isJwtExpired,
        verifyJwtAndRole: jwtLib.verifyJwtAndRole,
        doesJwtUserHasRole: jwtLib.doesJwtUserHasRole,
        validateAndExtractJwtObject: jwtLib.validateAndExtractJwtObject,
    }
};

