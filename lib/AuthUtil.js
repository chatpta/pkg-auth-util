const crypto = require('crypto');

class AuthUtil {
    constructor() {

    }

    /**
     * Creates the base64 hash of given string
     * HMAC does not encrypt the message.
     * Every time same string with same key should give the same hash
     * outputs base64 string
     */
    createHmacString(string = '', algorithm = 'sha512', key = 'dev-secret', outputType = 'base64') {
        return crypto.createHmac(algorithm, key)
            .update(string)
            .digest(outputType);
    };

    /**
     * Create random salt
     * Uses time as input to produce random string
     * @returns {string}
     */
    createRandomSalt() {
        return this.createHmacString(new Date().valueOf().toString());
    };

}

module.exports = AuthUtil;