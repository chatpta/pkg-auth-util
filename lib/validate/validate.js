class Validate {
    validateStringForCharactersPermittedInJwt(jwt) {
        if (jwt === '' || jwt.trim() === '') return false;
        const jwtRegex = /^eyJ[a-zA-Z0-9-_.]+$/;
        return jwtRegex.test(jwt);
    }
}

module.exports = Validate;