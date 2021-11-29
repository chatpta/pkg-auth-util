const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const { stringUtilAuth } = require( '../index' );


describe( 'ProcessJwt test', function () {
    it( 'makeStringUrlSafe returns url safe string', function ( done ) {
        const urlUnsafeString = "eyJhbGciOiJzaGE1MTIiL/CJ0e+XAiOiJKV1QifQ.eyJpZkkCI6IjEyMz===";
        const urlSafeString = "eyJhbGciOiJzaGE1MTIiL_CJ0e-XAiOiJKV1QifQ.eyJpZkkCI6IjEyMz";

        const returnedString = stringUtilAuth.makeStringUrlSafe( urlUnsafeString );
        assert.deepStrictEqual( returnedString, urlSafeString );
        done();
    } );

    it( 'reverseStringUrlSafe returns url safe string', function ( done ) {
        const urlSafeString = "eyJhbGciOiJzaGE1MTIiL_CJ0e-XAiOiJKV1QifQ.eyJpZkkCI6IjEyMz";
        const urlUnsafeString = "eyJhbGciOiJzaGE1MTIiL/CJ0e+XAiOiJKV1QifQ.eyJpZkkCI6IjEyMz===";

        const returnedString = stringUtilAuth.reverseStringUrlSafe( urlSafeString );
        assert.deepStrictEqual( returnedString, urlUnsafeString );
        done();
    } );

    it( 'asciiToBase64 returns base 64 string', function ( done ) {
        const asciiString = "How are you";
        const base64String = "SG93IGFyZSB5b3U=";

        const returnedString = stringUtilAuth.asciiToBase64( asciiString );
        assert.deepStrictEqual( returnedString, base64String );
        done();
    } );

    it( 'base64ToAscii returns ascii string', function ( done ) {
        const base64String = "SG93IGFyZSB5b3U=";
        const asciiString = "How are you";

        const returnedString = stringUtilAuth.base64ToAscii( base64String );
        assert.deepStrictEqual( returnedString, asciiString );
        done();
    } );

    it( 'dotConnectedStringToAlgorithmHashSalt split at . returns object', function ( done ) {
        const inputString = "c2hhNTEy.eyJhbGciOiJzaG.OiJzaGE1MTIiL";
        const expectedObject = {
            algorithm: 'c2hhNTEy',
            hash: 'eyJhbGciOiJzaG',
            salt: 'OiJzaGE1MTIiL'
        };

        const returnedObject = stringUtilAuth.dotConnectedStringToAlgorithmHashSalt( inputString );
        assert.deepStrictEqual( expectedObject, returnedObject );
        done();
    } );

    it( 'dotConnectedStringToAlgorithmHashSalt split at . returns object', function ( done ) {
        const inputString = "c2hhNTEy.eyJhbGciOiJzaG.OiJzaGE1MTIiL";
        const expectedObject = {
            header: 'c2hhNTEy',
            payload: 'eyJhbGciOiJzaG',
            signature: 'OiJzaGE1MTIiL'
        };

        const returnedObject = stringUtilAuth.dotConnectedStringToHeaderPayloadSignature( inputString );
        assert.deepStrictEqual( expectedObject, returnedObject );
        done();
    } );
} );
