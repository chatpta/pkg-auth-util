'use strict';
/**
 * For incoming jwt token are validation, splitting and parsing.
 * For outgoing jwt token assembling to jwt, make it url safe.
 */

/**
 * Removes /, + and = from the string
 * @returns {string}
 */
const makeStringUrlSafe = ( urlUnsafeString = '' ) => {
    return urlUnsafeString
        .replaceAll( '+', '-' )
        .replaceAll( '/', '_' )
        .replaceAll( '=', '' );
};

/**
 * Put back /, + and = into the string
 * @returns {string}
 */
const reverseStringUrlSafe = ( urlSafeString = '' ) => {
    let myString = urlSafeString
        .replaceAll( '-', '+' )
        .replaceAll( '_', '/' );
    while ( myString.length % 4 ) myString += '=';
    return myString;
};

module.exports = {
    makeStringUrlSafe,
    reverseStringUrlSafe
};
