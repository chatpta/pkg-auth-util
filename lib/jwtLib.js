const validate = require( '@chatpta/validate' );
const jwtUtilAuth = require( './jwtUtilAuth' );

function jwtClientId( req ) {

    return req?.jwt?.payload?.client_id;

}

function doesJwtUserHasRole( req, userRole ) {

    return req?.jwt?.payload?.roles?.includes( userRole );

}

function isJwtExpired( req, jwtValiditySeconds ) {

    return ( jwtValiditySeconds * 1000 ) < jwtAgeInMilliseconds( req );

}

function jwtAgeInMilliseconds( req ) {

    if ( req?.jwt?.payload?.iat ) {

        req.jwt[ "age" ] = Date.now() - req.jwt.payload.iat;
        return req.jwt.age;

    } else {

        req.jwt[ "age" ] = Infinity
        return req.jwt.age;

    }
}

async function validateAndExtractJwtObject( req, publicKey ) {

    const jwtString = await _validateJwt( req );

    const isJwtSignatureValid = await _isJwtSignatureValid( jwtString, publicKey );

    if ( jwtString && isJwtSignatureValid ) {
        await _extractJwtObject( req, jwtString );
    }

    return req;
}

function verifyJwtAndRole( role, publicKey, customErrorFunction ) {
    return async function ( req, res, next ) {
        await validateAndExtractJwtObject( req, publicKey )
            .then( req => doesJwtUserHasRole( req, role ) )
            .then( isRoleExist => _isLoginRequired( isRoleExist, customErrorFunction ) )
            .then( next )
            .catch( next );
    }
}

/*********************
 * Private functions *
 *********************/
function _isLoginRequired( hasRequiredRole, customErrorFunction ) {

    if ( hasRequiredRole ) {
        return;
    }

    customErrorFunction();

}

async function _extractJwtObject( req, jwt ) {
    if ( jwt && typeof jwt === "string" ) {
        req[ "jwt" ] = jwtUtilAuth.getHeaderPayloadFromJwt( jwt );
    } else {
        req[ "jwt" ] = null;
    }
}

async function _isJwtSignatureValid( jwt, publicKey ) {

    if ( jwt && typeof jwt === "string" ) {
        return jwtUtilAuth.verifyJwtSignature( jwt, publicKey )
    }

    return false;
}

async function _validateJwt( req ) {

    // Get from http header.
    let jwtRaw = req.get( "Authorization" );

    // Extract jwt from bearer schema.
    let jwt = _extractJwt( jwtRaw );

    // Validate characters string of jwt.
    if ( validate.isJwtString( jwt ) ) {
        return jwt;
    }

    return null;
}

function _extractJwt( jwtRaw ) {
    let jwtSplit = null;
    if ( jwtRaw && typeof jwtRaw === "string" ) {
        jwtSplit = jwtRaw.split( " " );
    }

    if ( jwtSplit[ 0 ].toLowerCase() === "bearer" ) {
        return jwtSplit[ 1 ];
    }

    return null;
}

module.exports = {
    _validateJwt,
    _isJwtSignatureValid,
    _extractJwtObject,
    validateAndExtractJwtObject,
    jwtAgeInMilliseconds,
    isJwtExpired,
    doesJwtUserHasRole,
    jwtClientId,
    verifyJwtAndRole
}
