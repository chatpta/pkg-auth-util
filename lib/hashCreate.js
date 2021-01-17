const crypto = require('crypto');

class HashCreate {
    constructor(defaultValues = {}) {
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
     * return null if error
     * @param passwordHash
     */
    decomposePasswordHash(passwordHash) {
        const splitHash = passwordHash.split('.');
        if (splitHash.length !== 3) return null;
        return {
            algorithm: splitHash[0].slice(1),
            hash: splitHash[1],
            salt: splitHash[2]
        };
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
        const splitHash = this.decomposePasswordHash(passwordHash);
        // Use algorithm and salt to calculate hash of password
        const passwordHashCalculated = this.createPasswordHash(password, splitHash.salt, secretKey, splitHash.algorithm);
        // return verify both are equal
        return (passwordHash === passwordHashCalculated);
    }
}

module.exports = HashCreate;