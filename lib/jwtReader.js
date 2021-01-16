const crypto = require('crypto');

class JwtReader {
    constructor(defaultValues = {}) {
        this.defaultAlgorithm = defaultValues.defaultAlgorithm || 'sha512';
        this.defaultSecret = defaultValues.defaultSecret || 'dev-secret';
        this.defaultOutputType = defaultValues.defaultOutputType || 'base64';
    }

    /**
     * Returns true is jwt is expired
     * @param jwt
     * @param validitySec
     */
    jwtIsExpired(jwt, validitySec) {
        try {
            const splitJWT = jwt.split('.');
            if (splitJWT.length !== 3) return null;
            let [header, payload, signature] = splitJWT;
            if (!!header) {
                payload = this.reverseStringUrlSafe(payload);
                payload = JSON.parse(this.base64ToAscii(payload));
                return ((!!payload) && (!!payload.time) && (payload.time > (Date.now() - (validitySec * 1000))));
            } else {
                return null;
            }
        } catch (err) {
            throw err;
        }
    }

    /**
     * Returns true if signature is valid
     * @param jwt
     * @param secret
     */
    jwtIsSignatureValid(jwt, secret = this.defaultSecret) {
        try {
            const splitJWT = jwt.split('.');
            if (splitJWT.length !== 3) return null;
            let [header, payload, signature] = splitJWT;
            if (!!header && !!payload && !!signature) {
                let reversedSignature = this.reverseStringUrlSafe(signature);
                let headerObject = JSON.parse(this.base64ToAscii(header));
                let calculatedSignature = this.createHmacString(header + '.' + payload, secret, headerObject.alg);
                return (calculatedSignature === reversedSignature);
            } else {
                return false;
            }
        } catch (err) {
            throw err;
        }
    }

    /**
     * Returns object {header: ..., payload: ...}
     * @param jwt
     */
    jwtRead(jwt) {
        try {
            const splitJWT = jwt.split('.');
            if (splitJWT.length !== 3) return null;
            let [header, payload, signature] = splitJWT;
            if (!!header && !!payload) {
                header = this.reverseStringUrlSafe(header);
                payload = this.reverseStringUrlSafe(payload);
                header = JSON.parse(this.base64ToAscii(header));
                payload = JSON.parse(this.base64ToAscii(payload));
                return {header, payload};
            } else {
                return null;
            }
        } catch (err) {
            throw err;
        }
    }

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

    /** Decode string from base64
     * @param codedString
     * @returns {string}
     */
    base64ToAscii(codedString) {
        return Buffer.from(codedString, 'base64').toString('ascii');
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

}

module.exports = JwtReader;