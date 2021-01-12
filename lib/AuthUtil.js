const crypto = require('crypto');

class AuthUtil {
    constructor(defaultAlgorithm, defaultSecret, defaultOutputType) {
        this.defaultAlgorithm = defaultAlgorithm || 'sha512';
        this.defaultSecret = defaultSecret || 'dev-secret';
        this.defaultOutputType = defaultOutputType || 'base64';
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


}

module.exports = AuthUtil;