
function generate_login_token(email, password) {
    var n = 16384;
    var r = 8;
    var p = 1;
    var l = 64;
    // takes the email address basically as salt. sha512 is used to enforce minimum length
    var salt = CryptoJS.SHA512(email.toLowerCase());

    var scrypt = scrypt_module_factory();

    return scrypt.to_hex(scrypt.crypto_scrypt(scrypt.encode_utf8(password), scrypt.encode_utf8(salt), n, r, p, l));
}
