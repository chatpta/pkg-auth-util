const { describe, it } = require( "mocha" );
const assert = require( "assert" );
const jwt = require( '../lib/jwtLib' );
const { publicKey } = require( "./keys" );

describe( "Lib controller jwt", function () {

    const jwtString = "eyJhbGciOiJzaGE1MTIiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2Mzg2NjIzMTQ5OTMsImNsaWVudF9pZCI6IjhiMGRiO" +
        "Dc3LWE2YjMtNGEyMy1hNDkzLWU2ODc5MTVjZGQ4NyIsInJvbGVzIjpbXX0.JmXjeU-D1-V0Wd5upURf1K72iXGuVuq5tUkHp0TqRiN1xwg6" +
        "RUhzB9HqBnsSgOyDt1BFhr-GPZdomPG0YHW8x8eza-46efledv2gl24ZT2uP-X9V70G-UVGcj8qDQZzP7u_ZkCY3SxA3Tzv7s_V6mAzVuBQ" +
        "vm5ga93fh2HwHEoE";

    it( "validateJwt", async function () {


        // Arrange
        const req = {
            get( header ) {
                if ( header === "Authorization" ) {
                    return "Bearer " + jwtString
                }
            }
        };
        const res = {
            send( message ) {
                this.body = message
            }
        };
        const next = () => {
        }

        // Act
        const receivedJwt = await jwt._validateJwt( req );

        // Assert
        assert.deepStrictEqual( receivedJwt, jwtString );
    } );

    it( "verifyJwtSignature", async function () {

        // Act
        const isSignatureValid = await jwt._isJwtSignatureValid( jwtString, publicKey );

        // Assert
        assert.deepStrictEqual( isSignatureValid, true );
    } );

    it( "extractJwtObject", async function () {
        // Arrange
        const req = {
            get( header ) {
                if ( header === "Authorization" ) {
                    return "Bearer " + jwtString
                }
            }
        };

        const expectedJwt = {
            header: { alg: 'sha512', typ: 'JWT' },
            payload: {
                iat: 1638662314993,
                client_id: '8b0db877-a6b3-4a23-a493-e687915cdd87',
                roles: []
            }
        }

        // Act
        await jwt._extractJwtObject( req, jwtString );

        // Assert
        assert.deepStrictEqual( req.jwt, expectedJwt );
    } );

    it( "validateAndExtractJwtObject", async function () {

        // Arrange
        const req = {
            get( header ) {
                if ( header === "Authorization" ) {
                    return "Bearer " + jwtString
                }
            }
        };

        const expectedJwt = {
            header: { alg: 'sha512', typ: 'JWT' },
            payload: {
                iat: 1638662314993,
                client_id: '8b0db877-a6b3-4a23-a493-e687915cdd87',
                roles: []
            }
        }

        // Act
        await jwt.validateAndExtractJwtObject( req, publicKey );

        // Assert
        assert.deepStrictEqual( req.jwt, expectedJwt );
    } );

    it( "jwtAgeInMilliseconds", async function () {

        // Arrange
        const req = { jwt: { payload: { iat: 1638662314993 } } };

        // Act
        let age = jwt.jwtAgeInMilliseconds( req );

        // Assert
        assert( age > 1000000 );
    } );

    it( " isJwtExpired", async function () {

        // Arrange
        const req = { jwt: { payload: { iat: 1638677253179 } } };
        const validityInSeconds = 30;

        // Act
        let isExpired = jwt.isJwtExpired( req, validityInSeconds );

        // Assert
        assert( isExpired );
    } );

    it( "isJwtUserHasRole", async function () {

        // Arrange
        const req = { jwt: { payload: { roles: [ "admin" ] } } };
        const role = "admin";
        const roleTwo = "none";

        // Act
        let hasRole = jwt.isJwtUserHasRole( req, role );
        let hasRoleTwo = jwt.isJwtUserHasRole( req, roleTwo );

        // Assert
        assert( hasRole );
        assert( !hasRoleTwo );
    } );

    it( "jwtClientId", async function () {

        // Arrange
        const req = { jwt: { payload: { client_id: '8b0db877-a6b3-4a23-a493-e687915cdd87'} } };

        // Act
        let clientId = jwt.jwtClientId( req );

        // Assert
        assert.deepStrictEqual( clientId, '8b0db877-a6b3-4a23-a493-e687915cdd87' );
    } );
} );
