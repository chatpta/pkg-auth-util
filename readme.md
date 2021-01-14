# Auth utilities class

## Main Functionality

This is a collection of utility functions for use in authentication

### Main functions

####Constructor takes default values object

```js
const defaultValues = {
    defaultAlgorithm: 'sha512',
    defaultSecret: 'dev-secret',
    defaultOutputType: 'base64'
};

const authUtil = new AuthUtil(defaultValues);

```

####Creates hash of password -> returns string 
- this string contains $algorithm.hash.salt

```js
createPasswordHash(password, secretKey, algorithm, outputType)
```

####Verify hash -> returns true or false
- Password: user password
- passwordHash: hash stored in the database as it is -> created by createPasswordHash() function
- secretKey: optional key, if different then the key used at initialization

```js
verifyPasswordHash(password, passwordHash, secretKey)
```

####Create JWT -> returns url safe jwt string
- This string follows jwt specification

```js
createJWT(header, payload, key)
```

#### verify JWT signatures -> returns true or false
- Returns true or false

```js
verifySignatureJWT(jwt, key)
```

####read JWT -> return object containing header, payload, signature
- Returns object containing { header: {}, payload: {} }

```js
readJWT(jwt)
```