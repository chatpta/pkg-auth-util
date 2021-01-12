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
    createHmacString(string = '',
                     secretKey = this.defaultSecret,
                     algorithm = this.defaultAlgorithm,
                     outputType = this.defaultOutputType) {
        return crypto.createHmac(algorithm, secretKey)
            .update(string)
            .digest(outputType);
    };

    /**
     * Create random salt
     * Uses time as input to produce random string
     * @returns {string}
     */
    createRandomSalt(string = new Date().valueOf().toString(),
                     secretKey = this.defaultSecret,
                     algorithm = this.defaultAlgorithm,
                     outputType = this.defaultOutputType) {
        return this.createHmacString(string, secretKey, algorithm, outputType);
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

    /** Creates password hash
     * $algorithm.hash.salt
     * @param password
     * @param salt
     * @param secretKey
     * @param algorithm
     * @param outputType
     */
    createPasswordHash(password = '',
                       salt = '',
                       secretKey = this.defaultSecret,
                       algorithm = this.defaultAlgorithm,
                       outputType = this.defaultOutputType) {
        // All algorithm in the beginning
        let hashString = '$' + algorithm;
        // Add salt to password
        let passwordWithSalt = password + salt;
        // Calculate hash on that
        // Add this hash to string separated by '.'
        hashString += '.' + this.createHmacString(passwordWithSalt, secretKey, algorithm, outputType);
        // Add salt to the string separated by '.'
        return hashString + '.' + salt;
    }

    /**
     * Decompose password hash and return an object with
     * {algorithm: 'something', hash: 'some-hash', salt: 'some-salt'}
     * @param passwordHash
     */
    decomposePasswordHash(passwordHash) {

    }

    /** Verifies hash of the given password
     * true or false
     * @param password
     * @param passwordHash
     * @param secretKey
     */
    verifyPasswordHash(password,
                       passwordHash,
                       secretKey = this.defaultSecret) {
        // Decompose given passwordHash into algorithm, hash and salt
        // Use algorithm and salt to calculate hash of password
        // Verify both are equal
    }
}

module.exports = AuthUtil;