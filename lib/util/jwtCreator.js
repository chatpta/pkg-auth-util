const Hash = require('./hash');
const commonUtil = require('./commonUtil');

class JwtCreator extends Hash {
    constructor(defaultValues) {
        super(defaultValues);
    }

    /**
     * User supplied header and algorithm create jwt
     * @param header
     * @param payload
     * @param secret
     * @returns {string|null}
     */
    jwtCreate(header, payload, secret = this.defaultSecret) {
        try {
            if ((!!header) && (!!payload) && (!!secret)) {
                let headerPlusPayloadUrlSafe = this.headerPayloadUrlSafeStringCreate(header, payload);
                let signature = this.createHmacString(headerPlusPayloadUrlSafe, secret, header.alg || this.defaultAlgorithm);
                let signatureUrlSafe = commonUtil.makeStringUrlSafe(signature);
                return headerPlusPayloadUrlSafe + '.' + signatureUrlSafe;
            } else {
                return null;
            }
        } catch (err) {
            throw err;
        }
    }

    /**
     * Creates SHA512 JWT which is url safe
     * @param header
     * @param payload
     * @param secret
     * @returns {string|null}
     */
    jwtCreateSHA512(header = {}, payload, secret = this.defaultSecret) {
        try {
            if ((!!header) && (!!payload) && (!!secret)) {
                let headerPlusPayloadUrlSafe = this.headerPayloadUrlSafeStringCreate({
                    ...header,
                    "alg": "sha512",
                    "typ": "JWT"
                }, {
                    ...payload,
                    "time": Date.now()
                });
                let signatureUrlSafe = commonUtil.makeStringUrlSafe(this.createHmacString(headerPlusPayloadUrlSafe, secret, 'sha512'));
                return headerPlusPayloadUrlSafe + '.' + signatureUrlSafe;
            } else {
                return null;
            }
        } catch (err) {
            throw err;
        }
    }

    /**
     * Create jwt just from the body no header needed
     * @param payload
     * @param secretKey
     * @returns {string|null}
     */
    jwtCreateFromPayloadSHA512(payload, secretKey = this.defaultSecret) {
        return this.jwtCreateSHA512({}, payload, secretKey);
    }

    /**
     * Returns base64 url safe header '.' payload string
     * @param header
     * @param payload
     * @returns {string|null}
     */
    headerPayloadUrlSafeStringCreate(header, payload) {
        try {
            if ((!!header) && (!!payload)) {
                let headerString = JSON.stringify(header);
                let base64Header = commonUtil.asciiToBase64(headerString);
                let payloadString = JSON.stringify(payload);
                let base64Payload = commonUtil.asciiToBase64(payloadString);
                return commonUtil.makeStringUrlSafe((base64Header + '.' + base64Payload));
            } else {
                return null;
            }
        } catch (err) {
            throw err;
        }
    }
}

module.exports = JwtCreator;