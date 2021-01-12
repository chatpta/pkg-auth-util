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
createPasswordHash(password, salt, algorithm)
```

Verify hash -> returns true or false

```js
verifyHashOfPassword(password, hashOfPassword)
```

Create JWT -> returns url safe jwt string

```js
createJWT(header, payload, key)
```

verify JWT signatures -> returns true or false

```js
createJWT(header, payload, key)
```

read JWT -> return header and payload object minus signature

```js
readJWT(jwt)
```