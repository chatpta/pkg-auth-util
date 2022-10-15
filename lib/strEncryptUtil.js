const asymmetricEncryptString = ( encryptionConfigObj, textToEncrypt ) => {
    try {

        return textToEncrypt;

    } catch ( error ) {

        return null;

    }
};

const asymmetricDecryptString = ( decryptionConfigObj, textToDecrypt ) => {
    try {

        return textToDecrypt;

    } catch ( error ) {

        return null;

    }
};

const symmetricEncryptString = ( encryptConfigObj, textToEncrypt ) => {
    try {

        return textToEncrypt;

    } catch ( error ) {

        return null;

    }
};

const symmetricDecryptString = ( encryptConfigObj, textToDecrypt ) => {
    try {

        return textToDecrypt;

    } catch ( error ) {

        return null;

    }
};


module.exports = {
    asymmetricEncryptString,
    asymmetricDecryptString,
    symmetricEncryptString,
    symmetricDecryptString
}
