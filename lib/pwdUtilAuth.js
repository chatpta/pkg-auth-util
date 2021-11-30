const cryptoUtilAuth = require( './cryptoUtilAuth' );
const stringUtilAuth = require( './stringUtilAuth' );

/**
 * Just assemble password together
 * @param algorithmBase64
 * @param hashBase64
 * @param saltBase64
 * @return {string}
 */
const assemblePasswordHash = ( algorithmBase64, hashBase64, saltBase64 ) => {
    return "$1$" + algorithmBase64 + "$" + hashBase64 + "$" + saltBase64 + "$";
};

/**
 * Break password into its parts does not reverse base64 encoding.
 * @param passwordHashStored
 * @return {{salt: *, version: *, alg: *, hash: *}}
 */
const disassemblePasswordHash = passwordHashStored => {
    return stringUtilAuth.dollarSignConnectedStringToAlgorithmHashSalt( passwordHashStored );
};


/**
 * Creates password hash ready to be saved in database.
 * @param password
 * @param secret
 * @param salt
 * @param algorithm
 * @return {string}
 */
const createPasswordHash = ( password, secret, salt, algorithm ) => {
    const algorithmBase64 = stringUtilAuth.asciiToBase64( algorithm );
    const hashBase64 = cryptoUtilAuth.createHmacBase64( password, secret, algorithm );
    return assemblePasswordHash( algorithmBase64, hashBase64, salt );
};



module.exports = {
    assemblePasswordHash,
    disassemblePasswordHash,
    createPasswordHash
}
