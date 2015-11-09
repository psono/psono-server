/**
   Some words in advance before you start implementing your own client that are really important:
   - Keep the clients password hidden at all costs
   - Keep the clients passwords sha256 hidden at all cost
   - Keep the clients passwords sha512 hidden at all cost
     ... and all other "weak" hashes of the users password! If you really really really need something coming from
     the users password, use "strong" hashes bcrypt / scrypt / ...
   - Never use a nonce twice
   - Never use the special sauce in any sha256 / sha512 besides for the reasons below as its an additional
     "hardening" of our implementation.
 */

var ClassClient = function (location, nacl_factory, jQuery, scrypt_module_factory) {
    "use strict";
    // Little Helper
    if (!location.origin) {
        location.origin = location.protocol + "//" + location.host;
    }

    /* Start of Config*/

    // Use current url, but should be hardcoded in production to something like:
    // 'https://dev.sanso.pw' or 'http://dev.sanso.pw:8001'
    // Please only use http instead of https for development purposes only and NEVER in production!
    var backend = location.origin;

    /* End of Config */

    var nacl = nacl_factory.instantiate();

    /* Im afraid people will send/use shaXXX hashes of their password for other purposes, therefore I add this special
     * sauce to every hash. This special sauce can be considered a constant and will never change. Its no secret but
     * it should not be used for anything else besides the reasons below */
    var special_sauce = 'c8db7c084e181fbd0c616ed445545375a40d9a3ddc3f9d8fac1dba860579cbc1';//sha256 of 'danielandsaschatryingtheirbest'

    /**
     * takes the sha512 of lowercase email (+ special sauce) as salt to generate scrypt password hash in hex called the
     * authkey, so basically:
     *
     * hex(scrypt(password, hex(sha512(lower(email)+special_sauce))))
     *
     * For compatibility reasons with other clients please use the following parameters if you create your own client:
     *
     * var n = 16384 // 2^14;
     * var r = 8;
     * var p = 1;
     * var l = 64;
     *
     * var special_sauce = 'c8db7c084e181fbd0c616ed445545375a40d9a3ddc3f9d8fac1dba860579cbc1'
     *
     * @param {string} email - email address of the user
     * @param {string} password - password of the user
     * @returns auth_key - scrypt hex value of the password with the sha512 of lowercase email as salt
     */
    this.generate_authkey = function (email, password) {

        var n = 16384; //2^14
        var r = 8;
        var p = 1;
        var l = 64; // 64 Bytes = 512 Bits

        var scrypt = scrypt_module_factory();

        // takes the email address basically as salt. sha512 is used to enforce minimum length
        var salt = nacl.to_hex(nacl.crypto_hash_string(email.toLowerCase() + special_sauce));

        return scrypt.to_hex(scrypt.crypto_scrypt(scrypt.encode_utf8(password), scrypt.encode_utf8(salt), n, r, p, l));
    };

    /**
     * generates secret keys that is 32 Bytes or 256 Bits long and represented as hex
     *
     * @returns {{public_key: string, private_key: string, secret_key: string}}
     */
    this.generate_secret_key = function () {

        return nacl.to_hex(nacl.random_bytes(32)); // 32 Bytes = 256 Bits
    };

    /**
     * generates public and private key pair
     * All keys are 32 Bytes or 256 Bits long and represented as hex
     *
     * @returns {{public_key: string, private_key: string}}
     */
    this.generate_public_private_keypair = function () {

        var pair = nacl.crypto_box_keypair();

        return {
            public_key : nacl.to_hex(pair.boxPk), // 32 Bytes = 256 Bits
            private_key : nacl.to_hex(pair.boxSk) // 32 Bytes = 256 Bits
        };
    };

    /**
     * Takes the secret and encrypts that with the provided password. The crypto_box takes only 256 bits, therefore we
     * are using sha256(password+special_sauce) as key for encryption.
     * Returns the nonce and the cipher text as hex.
     *
     * @param {string} secret
     * @param {string} password
     * @returns {{nonce: string, ciphertext: string}}
     */
    this.encrypt_secret = function (secret, password) {

        var k = nacl.crypto_hash_sha256(nacl.encode_utf8(password + special_sauce));
        var m = nacl.encode_utf8(secret);
        var n = nacl.crypto_secretbox_random_nonce();
        var c = nacl.crypto_secretbox(m, n, k);

        return {
            nonce: nacl.to_hex(n),
            ciphertext: nacl.to_hex(c)
        };

    };

    /**
     * Takes the cipher text and decrypts that with the nonce and the sha256(password+special_sauce).
     * Returns the initial secret.
     *
     * @param {string} ciphertext
     * @param {string} nonce
     * @param {string} password
     *
     * @returns {string} secret
     */
    this.decrypt_secret = function (ciphertext, nonce, password) {

        var k = nacl.crypto_hash_sha256(nacl.encode_utf8(password + special_sauce));
        var n = nacl.from_hex(nonce);
        var c = nacl.from_hex(ciphertext);
        var m1 = nacl.crypto_secretbox_open(c, n, k);

        return nacl.decode_utf8(m1);
    };

    /**
     * Takes the data and the secret_key as hex and encrypts the data.
     * Returns the nonce and the cipher text as hex.
     *
     * @param {string} data
     * @param {string} secret_key
     * @returns {{nonce: string, ciphertext: string}}
     */
    this.encrypt_data = function (data, secret_key) {

        var k = nacl.from_hex(secret_key);
        var m = nacl.encode_utf8(data);
        var n = nacl.crypto_secretbox_random_nonce();
        var c = nacl.crypto_secretbox(m, n, k);

        return {
            nonce: nacl.to_hex(n),
            ciphertext: nacl.to_hex(c)
        };
    };

    /**
     * Takes the cipher text and decrypts that with the nonce and the secret_key.
     * Returns the initial data.
     *
     * @param {string} ciphertext
     * @param {string} nonce
     * @param {string} secret_key
     *
     * @returns {string} data
     */
    this.decrypt_data = function (ciphertext, nonce, secret_key) {

        var k = nacl.from_hex(secret_key);
        var n = nacl.from_hex(nonce);
        var c = nacl.from_hex(ciphertext);
        var m1 = nacl.crypto_secretbox_open(c, n, k);

        return nacl.decode_utf8(m1);
    };

    /**
     * Takes the data and encrypts that with a random nonce, the receivers public key and users private key.
     * Returns the nonce and the cipher text as hex.
     *
     * @param {string} data
     * @param {string} public_key
     * @param {string} private_key
     * @returns {{nonce: string, ciphertext: string}}
     */
    this.encrypt_data_public_key = function (data, public_key, private_key) {

        var p = nacl.from_hex(public_key);
        var s = nacl.from_hex(private_key);
        var m = nacl.encode_utf8(data);
        var n = nacl.crypto_box_random_nonce();
        var c = nacl.crypto_box(m, n, p, s);

        return {
            nonce: nacl.to_hex(n),
            ciphertext: nacl.to_hex(c)
        };
    };

    /**
     * Takes the cipher text and decrypts that with the nonce, the senders public key and users private key.
     * Returns the initial data.
     *
     * @param {string} ciphertext
     * @param {string} nonce
     * @param {string} public_key
     * @param {string} private_key
     *
     * @returns {string} data
     */
    this.decrypt_data_public_key = function (ciphertext, nonce, public_key, private_key) {

        var p = nacl.from_hex(public_key);
        var s = nacl.from_hex(private_key);
        var n = nacl.from_hex(nonce);
        var c = nacl.from_hex(ciphertext);
        var m1 = nacl.crypto_box_open(c, n, p, s);

        return nacl.decode_utf8(m1);
    };

    /**
     * Ajax POST request to the backend with the email and authkey, returns nothing but an email is sent to the user
     * with an activation_code for the email
     *
     * @param {string} email - email address of the user
     * @param {string} authkey - authkey gets generated by generate_authkey(email, password)
     * @param {string} public_key - public_key of the public/private key pair for asymmetric encryption (sharing)
     * @param {string} private_key - private_key of the public/private key pair, encrypted with encrypt_secret
     * @param {string} private_key_nonce - the nonce for decrypting the encrypted private_key
     * @param {string} secret_key - secret_key for symmetric encryption, encrypted with encrypt_secret
     * @param {string} secret_key_nonce - the nonce for decrypting the encrypted secret_key
     * @returns {promise}
     */
    this.authentication_register = function (email, authkey, public_key, private_key, private_key_nonce, secret_key, secret_key_nonce) {
        var endpoint = '/authentication/register/';
        var type = "POST";
        var data = {
            email: email,
            authkey: authkey,
            public_key: public_key,
            private_key: private_key,
            private_key_nonce: private_key_nonce,
            secret_key: secret_key,
            secret_key_nonce: secret_key_nonce
        };

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: data,
            dataType: 'text' // will be json but for the demo purposes we insist on text
        });
    };

    /**
     * Ajax POST request to the backend with the activation_code for the email, returns nothing. If successful the user
     * can login afterwards
     *
     * @param activation_code
     * @returns {promise}
     */
    this.authentication_verify_email = function (activation_code) {
        var endpoint = '/authentication/verify-email/';
        var type = "POST";
        var data = {
            activation_code: activation_code
        };

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: data,
            dataType: 'text' // will be json but for the demo purposes we insist on text
        });
    };
    /**
     * Ajax POST request to the backend with email and authkey for login, returns the token for further authentication
     *
     * @param {string} email - email address of the user
     * @param {string} authkey - authkey gets generated by generate_authkey(email, password)
     * @returns {promise}
     */
    this.authentication_login = function (email, authkey) {
        var endpoint = '/authentication/login/';
        var type = "POST";
        var data = {
            email: email,
            authkey: authkey
        };

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: data,
            dataType: 'text' // will be json but for the demo purposes we insist on text
        });
    };

    /**
     * Ajax POST request to destroy the token and logout the user
     *
     * @param token
     * @returns {promise}
     */
    this.authentication_logout = function (token) {
        var endpoint = '/authentication/logout/';
        var type = "POST";

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: null, // No data required for get
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };

    /**
     * Ajax GET request with the token as authentication to get the current user's datastore
     *
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {uuid} [datastore_id=null] - the datastore ID
     * @returns {promise}
     */
    this.read_datastore = function (token, datastore_id) {

        //optional parameter datastore_id
        if (datastore_id === undefined) { datastore_id = null; }

        var endpoint = '/datastore/' + (datastore_id === null ? '' : datastore_id + '/');
        var type = "GET";

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: null, // No data required for get
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };


    /**
     * Ajax PUT request to create a datatore with the token as authentication and optional already some data,
     * together with the encrypted secret key and nonce
     *
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {string} [encrypted_data] - optional data for the new datastore
     * @param {string} [encrypted_data_nonce] - nonce for data, necessary if data is provided
     * @param {string} encrypted_data_secret_key - encrypted secret key
     * @param {string} encrypted_data_secret_key_nonce - nonce for secret key
     * @returns {promise}
     */
    this.create_datastore = function (token, encrypted_data, encrypted_data_nonce, encrypted_data_secret_key, encrypted_data_secret_key_nonce) {
        var endpoint = '/datastore/';
        var type = "PUT";
        var data = {
            data: encrypted_data,
            data_nonce: encrypted_data_nonce,
            secret_key: encrypted_data_secret_key,
            secret_key_nonce: encrypted_data_secret_key_nonce
        };

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: data,
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };

    /**
     * Ajax PUT request with the token as authentication and the new datastore content
     *
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {uuid} datastore_id - the datastore ID
     * @param {string} [encrypted_data] - optional data for the new datastore
     * @param {string} [encrypted_data_nonce] - nonce for data, necessary if data is provided
     * @param {string} [encrypted_data_secret_key] - encrypted secret key, wont update on the server if not provided
     * @param {string} [encrypted_data_secret_key_nonce] - nonce for secret key, wont update on the server if not provided
     *
     * @returns {promise}
     */
    this.write_datastore = function (token, datastore_id, encrypted_data, encrypted_data_nonce, encrypted_data_secret_key, encrypted_data_secret_key_nonce) {
        var endpoint = '/datastore/' + datastore_id + '/';
        var type = "POST";
        var data = {
            data: encrypted_data,
            data_nonce: encrypted_data_nonce,
            secret_key: encrypted_data_secret_key,
            secret_key_nonce: encrypted_data_secret_key_nonce
        };

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: data,
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };

    /**
     * Ajax GET request with the token as authentication to get the current user's secret
     *
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {uuid} [secret_id=null] - the secret ID
     *
     * @returns {promise}
     */
    this.read_secret = function (token, secret_id) {

        //optional parameter secret_id
        if (secret_id === undefined) { secret_id = null; }

        var endpoint = '/secret/' + (secret_id === null ? '' : secret_id + '/');
        var type = "GET";

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: null, // No data required for get
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };


    /**
     * Ajax PUT request to create a datatore with the token as authentication and optional already some data,
     * together with the encrypted secret key and nonce
     *
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {string} [encrypted_data] - optional data for the new secret
     * @param {string} [encrypted_data_nonce] - nonce for data, necessary if data is provided
     *
     * @returns {promise}
     */
    this.create_secret = function (token, encrypted_data, encrypted_data_nonce) {
        var endpoint = '/secret/';
        var type = "PUT";
        var data = {
            data: encrypted_data,
            data_nonce: encrypted_data_nonce
        };

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: data,
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };

    /**
     * Ajax PUT request with the token as authentication and the new secret content
     *
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {uuid} secret_id - the secret ID
     * @param {string} [encrypted_data] - optional data for the new secret
     * @param {string} [encrypted_data_nonce] - nonce for data, necessary if data is provided
     *
     * @returns {promise}
     */
    this.write_secret = function (token, secret_id, encrypted_data, encrypted_data_nonce) {
        var endpoint = '/secret/' + secret_id + '/';
        var type = "POST";
        var data = {
            data: encrypted_data,
            data_nonce: encrypted_data_nonce
        };

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: data,
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };

    /**
     * Ajax GET request with the token as authentication to get the current user's share
     *
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {uuid} [share_id=null] - the share ID
     *
     * @returns {promise}
     */
    this.read_share = function (token, share_id) {

        //optional parameter share_id
        if (share_id === undefined) { share_id = null; }

        var endpoint = '/share/' + (share_id === null ? '' : share_id + '/');
        var type = "GET";

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: null, // No data required for get
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };


    /**
     * Ajax PUT request to create a share with the token as authentication and optional already some data,
     * together with the encrypted secret key and nonce
     *
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {string} [encrypted_data] - optional data for the new share
     * @param {string} [encrypted_data_nonce] - nonce for data, necessary if data is provided
     * @param {string} encrypted_data_secret_key - encrypted secret key
     * @param {string} encrypted_data_secret_key_nonce - nonce for secret key
     * @returns {promise}
     */
    this.create_share = function (token, encrypted_data, encrypted_data_nonce, encrypted_data_secret_key, encrypted_data_secret_key_nonce) {
        var endpoint = '/share/';
        var type = "PUT";
        var data = {
            data: encrypted_data,
            data_nonce: encrypted_data_nonce,
            secret_key: encrypted_data_secret_key,
            secret_key_nonce: encrypted_data_secret_key_nonce
        };

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: data,
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };

    /**
     * Ajax PUT request with the token as authentication and the new share content
     *
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {uuid} share_id - the share ID
     * @param {string} [encrypted_data] - optional data for the new share
     * @param {string} [encrypted_data_nonce] - nonce for data, necessary if data is provided
     * @param {string} [encrypted_data_secret_key] - encrypted secret key, wont update on the server if not provided
     * @param {string} [encrypted_data_secret_key_nonce] - nonce for secret key, wont update on the server if not provided
     * @returns {promise}
     */
    this.write_share = function (token, share_id, encrypted_data, encrypted_data_nonce, encrypted_data_secret_key, encrypted_data_secret_key_nonce) {
        var endpoint = '/share/' + share_id + '/';
        var type = "POST";
        var data = {
            data: encrypted_data,
            data_nonce: encrypted_data_nonce,
            secret_key: encrypted_data_secret_key,
            secret_key_nonce: encrypted_data_secret_key_nonce
        };

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: data,
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };

    /**
     * Ajax GET request with the token as authentication to get the users and groups rights of the share
     *
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {uuid} share_id - the share ID
     * @returns {promise}
     */
    this.read_share_total = function (token, share_id) {
        var endpoint = '/share/rights/' + share_id + '/';
        var type = "GET";

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: null, // No data required for get
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };

    /**
     * Ajax GET request with the token as authentication to get the users and groups rights of the share
     *
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {uuid} share_id - the share ID
     * @param {uuid} user_id - the target user's user ID
     * @param {string} key - the encrypted share secret, encrypted with the public key of the target user
     * @param {string} nonce - the unique nonce for decryption
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {bool} read - read right
     * @param {bool} write - write right
     * @returns {promise}
     */
    this.create_share_right = function (token, share_id, user_id, key, nonce, read, write) {
        var endpoint = '/share/rights/' + share_id + '/';
        var type = "PUT";
        var data = {
            user_id: user_id,
            key: key,
            nonce: nonce,
            read: read,
            write: write
        };

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: data,
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };

    /**
     * Ajax GET request with the token as authentication to get the public key of a user by user_id or user_email
     *
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {uuid} [user_id] - the user ID
     * @param {uuid} [user_email] - the user email
     * @returns {promise}
     */
    this.get_users_public_key = function (token, user_id, user_email) {
        var endpoint = '/user/search/';
        var type = "POST";
        var data = {
            user_id: user_id,
            user_email: user_email
        };

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: data,
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };

    /**
     * Ajax GET request with the token as authentication to get the current user's groups
     *
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {uuid} [group_id=null] - the group ID
     * @returns {promise}
     */
    this.read_group = function (token, group_id) {

        //optional parameter group_id
        if (group_id === undefined) { group_id = null; }

        var endpoint = '/group/' + (group_id === null ? '' : group_id + '/');
        var type = "GET";

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: null, // No data required for get
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };


    /**
     * Ajax PUT request to create a group with the token as authentication and together with the name of the group
     *
     * @param {string} token - authentication token of the user, returned by authentication_login(email, authkey)
     * @param {string} name - name of the new group
     * @param {string} encrypted_data_secret_key - encrypted secret key
     * @param {string} encrypted_data_secret_key_nonce - nonce for secret key
     * @returns {promise}
     */
    this.create_group = function (token, name, encrypted_data_secret_key, encrypted_data_secret_key_nonce) {
        var endpoint = '/group/';
        var type = "PUT";
        var data = {
            name: name,
            secret_key: encrypted_data_secret_key,
            secret_key_nonce: encrypted_data_secret_key_nonce
        };

        return jQuery.ajax({
            type: type,
            url: backend + endpoint,
            data: data,
            dataType: 'text', // will be json but for the demo purposes we insist on text
            beforeSend: function (xhr) {
                xhr.setRequestHeader("Authorization", "Token " + token);
            }
        });
    };
};


