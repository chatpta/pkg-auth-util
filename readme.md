# Auth utilities class

## Main Functionality

This is a collection of utility functions for use in authentication

### Main functions

Constructor takes default values object

```js
const defaultValues = {
    defaultAlgorithm: 'sha512',
    defaultSecret: 'dev-secret',
    defaultOutputType: 'base64'
};

const authUtil = new AuthUtil(defaultValues);

```

Creates hash of password -> returns string this string contains $algorithm.hash.salt

```js
createPasswordHash(password, secretKey, algorithm, outputType)
```

Verify hash -> returns true or false

```js
verifyPasswordHash(password, passwordHash, secretKey)
```

Create JWT -> returns url safe jwt string

```js
createJWT(header, payload, key)
```

verify JWT signatures -> returns true or false

```js
verifySignatureJWT(jwt, key)
```

read JWT -> return object containing header, payload, signature

```js
readJWT(jwt)
```