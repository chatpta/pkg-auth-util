const crypto = require( "crypto" );


function createKey( key ) {
    return crypto.scryptSync( key, key, 24 );
}

const asymmetricEncryptString = ( encryptionConfigObj, textToEncrypt ) => {
    try {

        return textToEncrypt;

    } catch ( error ) {

        return error.code;

    }
};

const asymmetricDecryptString = ( decryptionConfigObj, textToDecrypt ) => {
    try {

        return textToDecrypt;

    } catch ( error ) {

        return error.code;

    }
};

const symmetricEncryptString = ( encryptConfigObj = {}, textToEncrypt ) => {
    try {

        const iv = Buffer.alloc( 16, 0 );

        const cipher = crypto.createCipheriv(
            encryptConfigObj.cipherAlgorithm,
            createKey( encryptConfigObj.encryptionKey ),
            iv
        );

        let encrypted = cipher.update(
            textToEncrypt,
            encryptConfigObj.encryptionInputEncoding,
            encryptConfigObj.encryptionOutputEncoding
        );

        encrypted += cipher.final( encryptConfigObj.encryptionOutputEncoding );

        return encrypted;

    } catch ( error ) {

        return error.code;

    }
};

const symmetricDecryptString = ( encryptConfigObj, textToDecrypt ) => {
    try {

        const iv = Buffer.alloc( 16, 0 );

        const decipher = crypto.createDecipheriv(
            encryptConfigObj.cipherAlgorithm,
            createKey( encryptConfigObj.encryptionKey ),
            iv
        );

        let decrypted = decipher.update(
            textToDecrypt,
            encryptConfigObj.encryptionOutputEncoding,
            encryptConfigObj.encryptionInputEncoding
        );

        decrypted += decipher.final( encryptConfigObj.encryptionInputEncoding );

        return decrypted;

    } catch ( error ) {

        return error.code;

    }
};


module.exports = {
    asymmetricEncryptString,
    asymmetricDecryptString,
    symmetricEncryptString,
    symmetricDecryptString
}
