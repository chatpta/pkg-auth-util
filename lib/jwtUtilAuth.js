/**
 * User supplied header and algorithm create jwt
 * @returns {string|null}
 * @param headerBase64
 * @param payloadBase64
 * @param secretBase64
 */
const assembleJwt = ( headerBase64, payloadBase64, secretBase64 ) => {
    return headerBase64 + "." + payloadBase64 + "." + secretBase64;
};

module.exports = {
    assembleJwt
};
