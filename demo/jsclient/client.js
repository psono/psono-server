
var client = {

    /**
     * takes the sha512 of lowercase email as salt to generate scrypt password hash in hex called the authkey
     *
     *   var n = 16384;
     *   var r = 8;
     *   var p = 1;
     *   var l = 64;
     *
     * @param {string} email - email address of the user
     * @param {string} password - password of the user
     * @returns auth_key - scrypt hex value of the password with the sha512 of lowercase email as salt
     */
    generate_login_authkey: function (email, password) {

        var n = 16384;
        var r = 8;
        var p = 1;
        var l = 64; // 64 Bytes = 512 Bits

        var scrypt = scrypt_module_factory();

        // takes the email address basically as salt. sha512 is used to enforce minimum length
        var salt = CryptoJS.SHA512(email.toLowerCase());

        return scrypt.to_hex(scrypt.crypto_scrypt(scrypt.encode_utf8(password), scrypt.encode_utf8(salt), n, r, p, l));
    }
};


