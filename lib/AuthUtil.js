const crypto = require('crypto');

class AuthUtil {
    constructor(defaultValues) {
        this.defaultAlgorithm = defaultValues.defaultAlgorithm || 'sha512';
        this.defaultSecret = defaultValues.defaultSecret || 'dev-secret';
        this.defaultOutputType = defaultValues.defaultOutputType || 'base64';
    }

    /**
     * Creates the base64 hash of given string
     * HMAC does not encrypt the message.
     * Every time same string with same key should give the same hash
     * outputs base64 string
     */
    createHmacString(string = '', algorithm = this.defaultAlgorithm, key = this.defaultSecret, outputType = this.defaultOutputType) {
        return crypto.createHmac(algorithm, key)
            .update(string)
            .digest(outputType);
    };

    /**
     * Create random salt
     * Uses time as input to produce random string
     * @returns {string}
     */
    createRandomSalt(string = new Date().valueOf().toString(), algorithm = this.defaultAlgorithm, key = this.defaultSecret, outputType = this.defaultOutputType) {
        return this.createHmacString(string, algorithm, key, outputType);
    };

    /**
     * Removes /, + and = from the string
     * @returns {string}
     */
    makeStringUrlSafe(urlUnsafeString = '') {
        return urlUnsafeString
            .replace('+', '-')
            .replace('/', '_')
            .replace(/=+$/, '');
    };

    /**
     * Put back /, + and = into the string
     * @returns {string}
     */
    reverseStringUrlSafe(urlSafeString = '') {
        let myString = urlSafeString
            .replace('-', '+')
            .replace('_', '/');
        while (myString.length % 4) myString += '=';
        return myString;
    };

    /**
     * Encode string to base64 string
     * @param unCodedString
     * @returns {string}
     */
    asciiToBase64(unCodedString) {
        return Buffer.from(unCodedString).toString('base64');
    }

    /** Decode string from base64
     * @param codedString
     * @returns {string}
     */
    base64ToAscii(codedString) {
        return Buffer.from(codedString, 'base64').toString('ascii');
    }


}

module.exports = AuthUtil;