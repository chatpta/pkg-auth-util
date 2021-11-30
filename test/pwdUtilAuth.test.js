const assert = require( 'assert' ).strict;
const { describe, it } = require( 'mocha' );
const { pwdUtilAuth } = require( '../index' );

describe( 'PwdUtilAuth test', function () {
    it( 'assemblePasswordHash called with algorithmBase64, hashBase64, saltBase64 returns password hash', function () {
        const algorithmBase64 = 'c2hhMjU2';
        const hashBase64 = 'c2hhMjU2';
        const saltBase64 = 'c2hhMjU2';
        const expectedHash = "$1$c2hhMjU2$c2hhMjU2$c2hhMjU2$";

        const returnedHash = pwdUtilAuth.assemblePasswordHash( algorithmBase64, hashBase64, saltBase64 );

        assert.deepStrictEqual( returnedHash, expectedHash );
    } );

    it( 'disassemblePasswordHash called with save hash', function () {
        const savedHash = "$1$c2hhMjU2$c2hhMjU$c2hhMjU2$";
        const hashBase64 = 'c2hhMjU';
        const saltBase64 = 'c2hhMjU2';

        const { version, alg, hash, salt } = pwdUtilAuth.disassemblePasswordHash( savedHash );

        assert.deepStrictEqual( salt, saltBase64 );
        assert.deepStrictEqual( hash, hashBase64 );
    } );

    it( 'createPasswordHash called with save hash', function () {
        const password = "mySecretPassword";
        const secret = 'bigSecret';
        const algorithm = 'sha512';
        const salt = "6h29BnpUkqfrmtnY1xUrAGZcpcAl5cUEJ4Qjj+BGXbo=";
        const expectedHash = "$1$c2hhNTEy$SOk/04Wn/ce1YIXHlUIqt5SgsuCCLIFjxpzHloVSxFh/z8JuLFshAaGNCkIRf47QSPCOJpkJ476N2eq1Yg1+yg==$6h29BnpUkqfrmtnY1xUrAGZcpcAl5cUEJ4Qjj+BGXbo=$";
        const hash = pwdUtilAuth.createPasswordHash( password, secret, salt, algorithm );

        assert.deepStrictEqual( hash, expectedHash );
    } );

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
