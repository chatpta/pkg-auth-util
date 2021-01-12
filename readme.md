# Auth utilities class

## Main Functionality

This is a collection of utility functions for use in authentication

### Main functions

Creates hash of password -> returns string 
```js
createPasswordHash(password, salt, algorithm)
```

Verify hash -> returns true or false
```js
verifyHashOfPassword(password, hashOfPassword)
```

Create JWT -> returns jwt string
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