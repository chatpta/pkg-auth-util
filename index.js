const pwdUtilAuth = require( './lib/pwdUtilAuth' );
const jwtUtilAuth = require( './lib/jwtUtilAuth' );
const strEncryptUtil = require( './lib/strEncryptUtil' );

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

    strEncryptUtil: {
        asymmetricEncryptString: strEncryptUtil.asymmetricEncryptString,
        asymmetricDecryptString: strEncryptUtil.asymmetricDecryptString,
        symmetricEncryptString: strEncryptUtil.symmetricEncryptString,
        symmetricDecryptString: strEncryptUtil.symmetricDecryptString
    },

    stringUtilAuth: require( './lib/stringUtilAuth' ),
};

