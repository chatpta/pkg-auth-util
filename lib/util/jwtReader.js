const crypto = require('crypto');
const JwtCreator = require('./jwtCreator');
const commonUtil = require('./commonUtil');

class JwtReader extends JwtCreator {
    constructor(defaultValues) {
        super(defaultValues);
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
                payload = commonUtil.reverseStringUrlSafe(payload);
                try {
                    payload = JSON.parse(commonUtil.base64ToAscii(payload));
                } catch (parseError) {
                    return false;
                }
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
                let reversedSignature = commonUtil.reverseStringUrlSafe(signature);
                let headerObject
                try {
                    headerObject = JSON.parse(commonUtil.base64ToAscii(header));
                } catch (parseError) {
                    return false;
                }
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
                header = commonUtil.reverseStringUrlSafe(header);
                payload = commonUtil.reverseStringUrlSafe(payload);
                try {
                    header = JSON.parse(commonUtil.base64ToAscii(header));
                    payload = JSON.parse(commonUtil.base64ToAscii(payload));
                } catch (parseError) {
                    return null;
                }
                return {header, payload};
            } else {
                return null;
            }
        } catch (err) {
            throw err;
        }
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