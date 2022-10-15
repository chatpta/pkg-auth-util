const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const { jwtUtilAuth, pwdUtilAuth, strEncryptUtil } = require( '../index' );
const keys = require( './keys/keys' );


describe( 'JwtUtilAuth', function () {

    it( 'createSignedJwtFromObject returns base64 url safe jwt', function () {
        const header = {
            alg: "SHA256",
            typ: "JWT"
        }
        const payload = {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022
        }
        const expectedJwt = "eyJhbGciOiJTSEEyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.E7BtILiVDoQ96-LHKtOVk9h7RMCTEYbJcQ9t0AMq_LnKR9hlE5cX5pUTl0HSAqfe3vrBN3tXxK6Zrx9kFYabWbA1l3vzUJ1Yiy5MsTtVIgRm9vw1QwtqOlY3ea31gLuWsKnGoexS3ng04z_HxviDmB2UZAsGKphc2S5OLDav5IY";

        const createdJwt = jwtUtilAuth.createSignedJwtFromObject( header, payload, keys.privateKey );

        assert.deepStrictEqual( createdJwt, expectedJwt );
    } );

    it( 'verifyJwtSignature returns true or false', function () {
        const jwt = "eyJhbGciOiJTSEEyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.E7BtILiVDoQ96-LHKtOVk9h7RMCTEYbJcQ9t0AMq_LnKR9hlE5cX5pUTl0HSAqfe3vrBN3tXxK6Zrx9kFYabWbA1l3vzUJ1Yiy5MsTtVIgRm9vw1QwtqOlY3ea31gLuWsKnGoexS3ng04z_HxviDmB2UZAsGKphc2S5OLDav5IY";

        const isVerified = jwtUtilAuth.verifyJwtSignature( jwt, keys.publicKey );

        assert.deepStrictEqual( isVerified, true );
    } );

    it( 'getHeaderPayloadFromJwt returns header, payload object', function () {
        const jwt = "eyJhbGciOiJTSEEyNTYiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.E7BtILiVDoQ96-LHKtOVk9h7RMCTEYbJcQ9t0AMq_LnKR9hlE5cX5pUTl0HSAqfe3vrBN3tXxK6Zrx9kFYabWbA1l3vzUJ1Yiy5MsTtVIgRm9vw1QwtqOlY3ea31gLuWsKnGoexS3ng04z_HxviDmB2UZAsGKphc2S5OLDav5IY";
        const expectedHeader = {
            alg: "SHA256",
            typ: "JWT"
        }
        const expectedPayload = {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
            "iat": 1516239022
        }

        const { header, payload } = jwtUtilAuth.getHeaderPayloadFromJwt( jwt );

        assert.deepStrictEqual( header, expectedHeader );
        assert.deepStrictEqual( payload, expectedPayload );
    } );
} );

describe( 'PwdUtilAuth', function () {

    it( 'createPasswordHashWithRandomSalt called with save hash', function () {
        const password = "mySecretPassword";
        const secret = 'bigSecret';
        const algorithm = 'sha512';

        const hash = pwdUtilAuth.createPasswordHashWithRandomSalt( password, secret, algorithm );

        assert.deepStrictEqual( hash.length > 40, true );
    } );

    it( 'createPasswordHashBasedOnSavedAlgorithmSalt called with saved hash', function () {
        const savedHash = "$1$c2hhNTEy$SOk/04Wn/ce1YIXHlUIqt5SgsuCCLIFjxpzHloVSxFh/z8JuLFshAaGNCkIRf47QSPCOJpkJ476N2eq1Yg1+yg==$6h29BnpUkqfrmtnY1xUrAGZcpcAl5cUEJ4Qjj+BGXbo=$";
        const password = "mySecretPassword";
        const secret = 'bigSecret';

        const hash = pwdUtilAuth.createPasswordHashBasedOnSavedAlgorithmSalt( password, savedHash, secret );

        assert.deepStrictEqual( hash, savedHash );
    } );
} );

describe( 'strEncryptUtil', function () {

    it( 'asymmetricEncryptString', function () {
        const textToEncrypt = 'This is some text for encryption';
        const encryptConfigObj = {
            cypherAlgorithm: "",
            encryptionKey: "",
            encryptionOutputCoding: ""
        }

        const hash = strEncryptUtil.asymmetricEncryptString( encryptConfigObj, textToEncrypt );

        // assert.deepStrictEqual( hash.length > 40, true );
    } );

    it( 'asymmetricDecryptString', function () {
        const textToDecrypt = 'This is some text for encryption';
        const decryptConfigObj = {
            cypherAlgorithm: "",
            encryptionKey: "",
            encryptionOutputCoding: ""
        }

        const hash = strEncryptUtil.asymmetricDecryptString( decryptConfigObj, textToDecrypt );

        // assert.deepStrictEqual( hash, savedHash );
    } );

    it( 'symmetricEncryptString', function () {
        const textToEncrypt = 'This is some text for encryption';
        const encryptConfigObj = {
            cypherAlgorithm: "",
            encryptionKey: "",
            encryptionOutputCoding: ""
        }

        const hash = strEncryptUtil.symmetricEncryptString( encryptConfigObj, textToEncrypt );

        // assert.deepStrictEqual( hash.length > 40, true );
    } );

    it( 'symmetricDecryptString', function () {
        const textToDecrypt = 'This is some text for encryption';
        const decryptConfigObj = {
            cypherAlgorithm: "",
            encryptionKey: "",
            encryptionOutputCoding: ""
        }

        const hash = strEncryptUtil.symmetricDecryptString( decryptConfigObj, textToDecrypt );

        // assert.deepStrictEqual( hash, savedHash );
    } );
} );
