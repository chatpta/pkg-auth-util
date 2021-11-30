const stringUtilAuth = require( './stringUtilAuth' );
const cryptoUtilAuth = require( './cryptoUtilAuth' );

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

/**
 * Creates Url safe jwt
 * @param header
 * @param payload
 * @param privateKey
 * @return {string|null}
 */
const createSignedJwtFromObject = ( header, payload, privateKey ) => {
    try {
        const algorithm = header.alg;
        const headerBase64UrlSafe = stringUtilAuth.objectToBase64UrlSafeString( header );
        const payloadBase64UrlSafe = stringUtilAuth.objectToBase64UrlSafeString( payload );
        const token = headerBase64UrlSafe + "." + payloadBase64UrlSafe;
        const signature = cryptoUtilAuth.createBase64SignatureOfToken( token, privateKey, algorithm );
        const urlSafeSignature = stringUtilAuth.makeStringUrlSafe( signature );
        return assembleJwt( headerBase64UrlSafe, payloadBase64UrlSafe, urlSafeSignature );
    } catch ( error ) {
        return null;
    }
};

/**
 * Verify signature of jwt
 * @param jwt
 * @param publicKey
 * @return {boolean}
 */
const verifyJwtSignature = ( jwt, publicKey ) => {
    try {
        const { header, payload, signature } = splitJwtInToHeaderPayloadSignature( jwt );
        const token = header + "." + payload;
        const headerObject = stringUtilAuth.urlSafeBase64ToObject( header );
        return cryptoUtilAuth.verifyBase64SignatureOfToken( token, signature, publicKey, headerObject.alg )
    } catch ( error ) {
        return false;
    }
};

module.exports = {
    assembleJwt,
    splitJwtInToHeaderPayloadSignature,
    createSignedJwtFromObject,
    verifyJwtSignature
};
