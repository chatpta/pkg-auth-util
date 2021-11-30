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

/**
 * Automatically adds random salt.
 * @param password
 * @param secret
 * @param algorithm
 * @return {string}
 */
const createPasswordHashWithRandomSalt = ( password, secret, algorithm ) => {
    const salt = cryptoUtilAuth.createSaltBase64();
    return createPasswordHash( password, secret, salt, algorithm );
};

/**
 * Creates hash based on saved hash in database.
 * @param password
 * @param savedPasswordHash
 * @param secret
 * @return {string}
 */
const createPasswordHashBasedOnSavedAlgorithmSalt = ( password, savedPasswordHash, secret ) => {
    const { version, alg, hash, salt } = disassemblePasswordHash( savedPasswordHash );
    const algorithm = stringUtilAuth.base64ToAscii( alg );
    return createPasswordHash( password, secret, salt, algorithm );
};


module.exports = {
    assemblePasswordHash,
    disassemblePasswordHash,
    createPasswordHash,
    createPasswordHashWithRandomSalt,
    createPasswordHashBasedOnSavedAlgorithmSalt
}
