const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const { processJwt } = require( '../index' );


describe( 'ProcessJwt test', function () {
    it( 'fromUrlSafeToBase64Jwt when called with url safe jwt returns base64 string', function ( done ) {
        const urlSafeJwt = "eyJhbGciOiJzaGE1MTIiLCJ0eXAiOiJKV1QifQ.eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0aW1lIjoxNjM4MjE0MDc0MDIzfQ.2t8UToQ6J-sIHUNH5XADFbdErSFeG8WEGj0FfR4YVnsQxnLJeDECtsNdj3IrMag2sNEEqqeuemycm1N70FrvHw";
        const base64Jwt = "";

        // const returnedBase64Jwt = processJwt.fromUrlSafeToBase64Jwt( urlSafeJwt );
        // assert.deepStrictEqual( returnedBase64Jwt, base64Jwt );
        done();
    } );
} );
