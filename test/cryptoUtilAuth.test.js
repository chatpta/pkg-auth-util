const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const { cryptoUtilAuth } = require( '../index' );
const keys = require( './keys' );


describe( 'CryptoUtilAuth test', function () {
    it( 'createBase64SignatureOfToken returns base64 signature of token', function () {
        const algorithm = 'SHA256';
        const token = "Hi I am token";
        const signature = "G3uHnG5DIoi3YWaj+umNmCtzAfBMmxAGfkWxlXP9qTfEr48qJjIVIdD5ic5T9YSDMt+6+XsembuL2NP6h4xoe+qE/wRjNKXCF6Hg/VvBciOdZyUqX8TaiAbGsh6J2d42rjX1vchrqfrBgCW5kiyeZcTic8LQeNdL/2gO+F9bW8A=";

        const returnedSignature = cryptoUtilAuth.createBase64SignatureOfToken( token, keys.privateKey, algorithm );

        assert.deepStrictEqual( returnedSignature, signature );
    } );

    it( 'verifyBase64SignatureOfToken returns true or false', function () {
        const algorithm = 'SHA256';
        const token = "Hi I am token";
        const signature = "G3uHnG5DIoi3YWaj+umNmCtzAfBMmxAGfkWxlXP9qTfEr48qJjIVIdD5ic5T9YSDMt+6+XsembuL2NP6h4xoe+qE/wRjNKXCF6Hg/VvBciOdZyUqX8TaiAbGsh6J2d42rjX1vchrqfrBgCW5kiyeZcTic8LQeNdL/2gO+F9bW8A=";
        const temperedSignature = "temper" + signature;
        const expectedValueTrue = true;
        const expectedValueFalse = false;

        const returnedValue = cryptoUtilAuth.verifyBase64SignatureOfToken( token, signature, keys.publicKey, algorithm );
        const returnedValueFalse = cryptoUtilAuth.verifyBase64SignatureOfToken( token, temperedSignature, keys.publicKey, algorithm );

        assert.deepStrictEqual( returnedValue, expectedValueTrue );
        assert.deepStrictEqual( returnedValueFalse, expectedValueFalse );
    } );
} );
