const jwtLib = require( './lib/jwtLib' )
const pwdUtilAuth = require( './lib/pwdUtilAuth' );

module.exports = {
    jwtUtilAuth: require( './lib/jwtUtilAuth' ),
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

