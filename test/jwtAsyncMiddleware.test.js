const { describe, it } = require( "mocha" );
const assert = require( "assert" );
const { publicKey } = require( "./keys" );
const { getJwtSignatureVerifyAndExtract } = require( "../lib/jwtAsyncMiddleware" );

describe( "Controller jwt", function () {

    const jwtString = "eyJhbGciOiJzaGE1MTIiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2Mzg2NjIzMTQ5OTMsImNsaWVudF9pZCI6IjhiMGRiO" +
        "Dc3LWE2YjMtNGEyMy1hNDkzLWU2ODc5MTVjZGQ4NyIsInJvbGVzIjpbXX0.JmXjeU-D1-V0Wd5upURf1K72iXGuVuq5tUkHp0TqRiN1xwg6" +
        "RUhzB9HqBnsSgOyDt1BFhr-GPZdomPG0YHW8x8eza-46efledv2gl24ZT2uP-X9V70G-UVGcj8qDQZzP7u_ZkCY3SxA3Tzv7s_V6mAzVuBQ" +
        "vm5ga93fh2HwHEoE";

    it( "jwtSignatureVerifyAndExtract", async function () {


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

        const expectedJwt = {
            header: { alg: 'sha512', typ: 'JWT' },
            payload: {
                iat: 1638662314993,
                client_id: '8b0db877-a6b3-4a23-a493-e687915cdd87',
                roles: []
            }
        };

        // Act

        const jwtSignatureVerifyAndExtract = getJwtSignatureVerifyAndExtract( publicKey );
        await jwtSignatureVerifyAndExtract( req, res, next );

        // Assert
        assert.deepStrictEqual( req.jwt, expectedJwt );
    } );
} );
