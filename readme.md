# Auth utilities class

## Main Functionality

This is a collection of utility functions for use in authentication

### Main functions

Create jwt

```js
const jwt = createSignedJwtFromObject( headerObject, payloadObject, privateKey );
```

Verify jwt signature returns ```true``` or ```false```

```js
const isVerified = verifyJwtSignature( jwt, publicKey );
```

Create password hash to save in database

```js
const hash = createPasswordHashWithRandomSalt( password, secret, algorithm );
```

Create another password hash based on saved hash to compare.

```js
const hashForLogin = createPasswordHashBasedOnSavedAlgorithmSalt( passwordForLogin, savedPasswordHash, secret );
```

