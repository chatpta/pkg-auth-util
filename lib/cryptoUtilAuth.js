const crypto = require( "crypto" );
/**
 * Signs a token returns signature string
 * @param token
 * @param privateKey
 * @param signingAlgorithm
 * @returns {string}
 */
const createBase64SignatureOfToken = function ( token = '', privateKey, signingAlgorithm ) {

    const sign = crypto.createSign( signingAlgorithm || 'SHA256' );
    sign.write( token );
    sign.end();
    return sign.sign( privateKey, 'base64' );
};

/**
 * Verifies the signature returns true or false
 * @param token
 * @param signature
 * @param publicKey
 * @param signingAlgorithm
 * @returns {boolean}
 */
const verifyBase64SignatureOfToken = function ( token = '', signature, publicKey, signingAlgorithm ) {
    const verify = crypto.createVerify( signingAlgorithm || 'SHA256' );
    verify.update( token );
    verify.end();
    return verify.verify( publicKey, signature, 'base64' );
};

/**
 * Creates the hash of given string
 * @param string
 * @param secret
 * @param algorithm
 * @returns {string}
 */
const createHmacBase64 = function ( string = '', secret, algorithm ) {
    const hmac = crypto.createHmac( algorithm || 'sha256', secret );
    hmac.update( string );
    return hmac.digest( 'base64' );
};

module.exports = {
    createBase64SignatureOfToken,
    verifyBase64SignatureOfToken,
    createHmacBase64
};
