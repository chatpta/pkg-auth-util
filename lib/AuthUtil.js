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
            .replaceAll('+', '-')
            .replaceAll('/', '_')
            .replaceAll('=', '');
    };

    /**
     * Put back /, + and = into the string
     * @returns {string}
     */
    reverseStringUrlSafe(urlSafeString = '') {
        let myString = urlSafeString
            .replaceAll('-', '+')
            .replaceAll('_', '/');
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

    /**
     * Returns url safe JWT signed with the secretKey
     * @param header
     * @param payload
     * @param secretKey
     */
    createJWT(header, payload, secretKey = this.defaultSecret) {
        // Create url safe header
        let headerString = JSON.stringify(header);
        let base64Header = this.asciiToBase64(headerString);
        let urlSafeHeader = this.makeStringUrlSafe(base64Header);
        // Create url safe payload
        let payloadString = JSON.stringify(payload);
        let base64Payload = this.asciiToBase64(payloadString);
        let urlSafePayload = this.makeStringUrlSafe(base64Payload);
        // Create url safe signature
        let headerPlusPayload = urlSafeHeader + '.' + urlSafePayload;
        let signature = this.createHmacString(headerPlusPayload, secretKey)
        let urlSafeSignature = this.makeStringUrlSafe(signature);
        // Create jwt and return
        return headerPlusPayload + '.' + urlSafeSignature;
    }

    /**
     * Returns true or false,
     * If token is tempered with returns false
     * If token is un tempered returns true
     * @param jwt
     * @param secretKey
     */
    verifySignatureJWT(jwt, secretKey = this.defaultSecret) {
        // Decompose jwt
        let jwtObject = this.decomposeJWT(jwt);
        // Header plus payload still url safe
        let headerPlusPayload = jwtObject.header + '.' + jwtObject.payload;
        // Calculate signatures
        let signatureCalculated = this.createHmacString(headerPlusPayload, secretKey);
        // Make signatures url safe
        let urlSafeSignature = this.makeStringUrlSafe(signatureCalculated);
        // Return comparison
        return (jwtObject.signature === urlSafeSignature);
    }

    /**
     * Decompose jwt and return an object with
     * {header: 'string', payload: 'string', signature: 'string'}
     * return null if error
     */
    decomposeJWT(jwt) {
        const splitJWT = jwt.split('.');
        if (splitJWT.length !== 3) return null;
        return {
            header: splitJWT[0],
            payload: splitJWT[1],
            signature: splitJWT[2]
        };
    }

    /**
     * Reads jwt and return object shown below
     * @param jwt
     * @returns {{payload: *|string, signature: *|string, header: *|string}}
     */
    readJWT(jwt) {
        // Decompose jwt
        const decomposedJWT = this.decomposeJWT(jwt);
        // Reverse url safe
        decomposedJWT.header = this.reverseStringUrlSafe(decomposedJWT.header);
        decomposedJWT.payload = this.reverseStringUrlSafe(decomposedJWT.payload);
        // Parse object from json
        decomposedJWT.header = JSON.parse(this.base64ToAscii(decomposedJWT.header));
        decomposedJWT.payload = JSON.parse(this.base64ToAscii(decomposedJWT.payload));
        return decomposedJWT;
    }
}

module.exports = AuthUtil;