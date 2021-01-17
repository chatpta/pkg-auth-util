/**
 * Put back /, + and = into the string
 * @returns {string}
 */
const reverseStringUrlSafe = (urlSafeString = '') => {
    let myString = urlSafeString
        .replaceAll('-', '+')
        .replaceAll('_', '/');
    while (myString.length % 4) myString += '=';
    return myString;
};

/** Decode string from base64
 * @param codedString
 * @returns {string}
 */
const base64ToAscii = (codedString) => {
    return Buffer.from(codedString, 'base64').toString('ascii');
}

/**
 * Encode string to base64 string
 * @param unCodedString
 * @returns {string}
 */
const asciiToBase64 = (unCodedString) => {
    return Buffer.from(unCodedString).toString('base64');
}

/**
 * Removes /, + and = from the string
 * @returns {string}
 */
const makeStringUrlSafe = (urlUnsafeString = '') => {
    return urlUnsafeString
        .replaceAll('+', '-')
        .replaceAll('/', '_')
        .replaceAll('=', '');
};

module.exports = {
    reverseStringUrlSafe,
    base64ToAscii,
    asciiToBase64,
    makeStringUrlSafe
};