const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const { jwtUtilAuth } = require( '../index' );
const keys = require( './keys' );


describe( 'JwtUtilAuth test', function () {
    it( 'assembleJwt called with header, payload and signature returns jwt', function () {
        const header = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9";
        const payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        const signature = "-DprLrW2OyqiAFiuWs14WO2TWp2EHtaX7a63dqrklk-xrjaZMrcPhpX4hkZw803SQx5HpGc-7VYBX8l82XlMZg";
        const expectedJwt = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.-DprLrW2OyqiAFiuWs14WO2TWp2EHtaX7a63dqrklk-xrjaZMrcPhpX4hkZw803SQx5HpGc-7VYBX8l82XlMZg";

        const returnedJwt = jwtUtilAuth._assembleJwt( header, payload, signature );
        assert.deepStrictEqual( returnedJwt, expectedJwt );
    } );

    it( 'splitJwtInToHeaderPayloadSignature splits jwt into its parts', function () {
        const jwt = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.-DprLrW2OyqiAFiuWs14WO2TWp2EHtaX7a63dqrklk-xrjaZMrcPhpX4hkZw803SQx5HpGc-7VYBX8l82XlMZg";
        const headerExpected = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9";
        const payloadExpected = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        const signatureExpected = "-DprLrW2OyqiAFiuWs14WO2TWp2EHtaX7a63dqrklk-xrjaZMrcPhpX4hkZw803SQx5HpGc-7VYBX8l82XlMZg";

        const { header, payload, signature } = jwtUtilAuth._splitJwtInToHeaderPayloadSignature( jwt );
        assert.deepStrictEqual( header, headerExpected );
        assert.deepStrictEqual( payload, payloadExpected );
        assert.deepStrictEqual( signature, signatureExpected );
    } );

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
