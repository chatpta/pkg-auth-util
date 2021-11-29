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

/**
 * Encode string to base64 string
 * @param unCodedString
 * @returns {string}
 */
const asciiToBase64 = ( unCodedString ) => {
    return Buffer.from( unCodedString ).toString( 'base64' );
}

/** Decode string from base64
 * @param codedString
 * @returns {string}
 */
const base64ToAscii = ( codedString ) => {
    return Buffer.from( codedString, 'base64' ).toString( 'ascii' );
}

/**
 * Decompose . connected string and return an object with
 * {algorithm: 'something', hash: 'some-hash', salt: 'some-salt'}
 * return null if error
 * @param passwordHash
 */
const dotConnectedStringToAlgorithmHashSalt = ( passwordHash ) => {
    const splitHash = passwordHash.split( '.' );
    if ( splitHash.length !== 3 ) return null;
    return {
        algorithm: splitHash[ 0 ],
        hash: splitHash[ 1 ],
        salt: splitHash[ 2 ]
    };
}

/**
 * Decompose . connected string and return an object with
 * {header: 'string', payload: 'string', signature: 'string'}
 * return null if error
 */
const dotConnectedStringToHeaderPayloadSignature = ( jwt ) => {
    const splitJWT = jwt.split( '.' );
    if ( splitJWT.length !== 3 ) return null;
    return {
        header: splitJWT[ 0 ],
        payload: splitJWT[ 1 ],
        signature: splitJWT[ 2 ]
    };
}


module.exports = {
    makeStringUrlSafe,
    reverseStringUrlSafe,
    asciiToBase64,
    base64ToAscii,
    dotConnectedStringToAlgorithmHashSalt,
    dotConnectedStringToHeaderPayloadSignature
};
