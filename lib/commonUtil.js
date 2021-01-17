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

module.exports = {reverseStringUrlSafe, base64ToAscii};