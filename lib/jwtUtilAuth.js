const stringUtilAuth = require( './stringUtilAuth' );

/**
 * User supplied header, payload and signature create jwt.
 * @returns {string|null}
 * @param headerBase64
 * @param payloadBase64
 * @param signatureBase64
 */
const assembleJwt = ( headerBase64, payloadBase64, signatureBase64 ) => {
    return headerBase64 + "." + payloadBase64 + "." + signatureBase64;
};

/**
 * User supplied header, payload and signature create jwt.
 * @returns {{payload: *, signature: *, header: *}}
 * @param jwt
 */
const splitJwtInToHeaderPayloadSignature = ( jwt ) => {
    return stringUtilAuth.dotConnectedStringToHeaderPayloadSignature( jwt );
};

module.exports = {
    assembleJwt,
    splitJwtInToHeaderPayloadSignature
};
