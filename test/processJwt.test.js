const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const { processJwt } = require( '../index' );


describe( 'ProcessJwt test', function () {
    it( 'makeStringUrlSafe returns url safe string', function ( done ) {
        const urlUnsafeString = "eyJhbGciOiJzaGE1MTIiL/CJ0e+XAiOiJKV1QifQ.eyJpZkkCI6IjEyMz===";
        const urlSafeString   = "eyJhbGciOiJzaGE1MTIiL_CJ0e-XAiOiJKV1QifQ.eyJpZkkCI6IjEyMz";

        const returnedString = processJwt.makeStringUrlSafe( urlUnsafeString );
        assert.deepStrictEqual( returnedString, urlSafeString );
        done();
    } );

    it( 'reverseStringUrlSafe returns url safe string', function ( done ) {
        const urlSafeString   = "eyJhbGciOiJzaGE1MTIiL_CJ0e-XAiOiJKV1QifQ.eyJpZkkCI6IjEyMz";
        const urlUnsafeString = "eyJhbGciOiJzaGE1MTIiL/CJ0e+XAiOiJKV1QifQ.eyJpZkkCI6IjEyMz===";

        const returnedString = processJwt.reverseStringUrlSafe( urlSafeString );
        assert.deepStrictEqual( returnedString, urlUnsafeString );
        done();
    } );
} );
