// const assert = require('assert').strict;
// const Validate = require('../../validate/validate');
//
//
// describe('Validate test', () => {
//     const validate = new Validate();
//
//     it('validate the jwt string that characters are only base 64 and . - _', async () => {
//         const goodJwt = 'eyJhbGciOiJzaGE1MTIiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyX2lkIjoyNjg0LCJ0aW1lIjoxNjEwNzE2ODM0ODc2fQ.9o_7dM4YjjcNseH7Cw3IL_t8yD1hhs1hluTCWG_JzYEExYOp89Gd6k0AbU018x3EQXCrdMUE6KXfL0KNg2Li9g';
//         const badJwt = 'eyJhbGciOiJza<scriptE1MTIiLCJ0eXAiOiJKV/1QifQ.eyJ1c2VyX2lkIjoyNjg0LCJ0aW1lIjoxNjEwNzE2ODM0ODc2fQ.9o_7dM4YjjcNseH7Cw3IL_t8yD1hhs1hluTCWG_JzYEExYOp89Gd6k0AbU018x3EQXCrdMUE6KXfL0KNg2Li9g';
//         assert(validate.validateStringForCharactersPermittedInJwt(goodJwt));
//         assert(!validate.validateStringForCharactersPermittedInJwt(badJwt));
//     });
// });
