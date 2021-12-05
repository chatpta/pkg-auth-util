'use strict';

const libJwt = require( './jwtLib' );


function getJwtSignatureVerifyAndExtract( publicKey ) {

    return async function jwtSignatureVerifyAndExtract( req, res, next ) {
        return await libJwt.validateAndExtractJwtObject( req, publicKey );
    }

}

module.exports = {
    getJwtSignatureVerifyAndExtract
}
