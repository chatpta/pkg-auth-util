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
        validateAndExtractJwtObject: jwtLib.validateAndExtractJwtObject,
        isJwtExpired: jwtLib.isJwtExpired,
        doesJwtUserHasRole: jwtLib.doesJwtUserHasRole,
        jwtClientId: jwtLib.jwtClientId
    }
};

