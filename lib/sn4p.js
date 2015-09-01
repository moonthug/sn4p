/**
 * Created by moonman
 *
 * Based on https://github.com/mgp25/SC-API
 */

///////////////////////////////////////////////////////////////////////////////
//
//
// DEPENDENCIES
//

// Package
var crypto      = require('crypto'),
    fs          = require('fs'),
    querystring = require('querystring');

// Library
var async   = require('async'),
    bigint  = require('bigint'),
    ursa    = require('ursa'),
    NodeRSA = require('node-rsa'),
    request = require('request');


///////////////////////////////////////////////////////////////////////////////
//
//
// IMPLEMENTATION
//

///////////////////////////////////////
//
// PUBLIC METHODS

var USER_AGENT          = 'Snapchat/9.14.2.0 (HTC One; Android 4.4.2#302626.7#19; gzip)',
    API_URL             = 'https://feelinsonice-hrd.appspot.com',
    SECRET              = 'iEk21fuwZApXlz93750dmW22pw389dPwOk',
    STATIC_TOKEN        = 'm198sOkJEn37DjqZ32lpRu76xmw288xSQ9',
    BLOB_ENCRYPTION_KEY = 'M02cnQ51Ji97vwT4',
    HASH_PATTERN        = '0001110111101110001111010101111011010001001110011000110001000110'; // Hash pattern



///////////////////////////////////////
//
// PUBLIC METHODS

var Sn4p = function(options) {
    this.googleCredentials = {
        email       : options.google.email,
        password    : options.google.password
    };
    this.snapchatCredentials = {
        username    : options.snapchat.username,
        password    : options.snapchat.password
    };

    this.authToken          = null;
    this.googleAuthToken    = '';
};

/**
 *
 * @param {function} cb
 */
Sn4p.prototype.login = function(cb) {
    var self        = this;
    var timestamp   = Date.now();

    async.waterfall([
        // Get device token
        function(next) {
            self._getDeviceToken(next);
        },

        // Get auth token
        function(deviceToken, next) {
            self._getAuthToken(function(err, data) {
                var authToken = data.auth;
                next(err, deviceToken, authToken);
            });
        },

        // Get Attestation
        function(deviceToken, authToken, next) {
            self._getAttestation(timestamp, function(err, data) {
                var attestation = data;
                next(err, deviceToken, authToken, attestation);
            });
        },

        // Get Client auth token
        function(deviceToken, authToken, attestation, next) {
            self._getClientAuthToken(timestamp, function(err, data) {
                var clientAuthToken = data;
                next(err, deviceToken, authToken, attestation, clientAuthToken);
            });
        },

        // Perform login
        function(deviceToken, authToken, attestation, clientAuthToken, next) {
            var reqToken    = self._hash(STATIC_TOKEN, timestamp),
                string      = self.snapchatCredentials.username +  '|' + self.snapchatCredentials.password + '|' + timestamp + '|' + reqToken;

            var signatureHmac = crypto.createHmac('sha256', deviceToken.dtoken1v);
            signatureHmac.update(string);

            var signature = signatureHmac.digest('hex');

            self._post(
                '/loq/login',
                {
                    'username'          : self.snapchatCredentials.username,
                    'password'          : self.snapchatCredentials.password,
                    'height'            : 1280,
                    'width'             : 720,
                    'max_video_height'  : 640,
                    'max_video_width'   : 480,
                    'dsig'              : signature.substr(0, 20),
                    'dtoken1i'          : deviceToken.dtoken1i,
                    'ptoken'            : 'ie',
                    'timestamp'         : timestamp,
                    'attestation'       : attestation,
                    'sflag'             : 1,
                    'application_id'    : 'com.snapchat.android',
                    'req_token'         : reqToken
                },
                [
                    STATIC_TOKEN,
                    timestamp,
                    authToken,
                    clientAuthToken
                ],
                false,
                function(err, results) {
                    if(err) return cb(err);

                    self.googleAuthToken = authToken;
                    self.authToken = results.updates_response.auth_token;
                    next();
                }
            );
        },

        // Set device
        function(next) {
            self.device(next);
        }
    ],
    cb);
};

/**
 *
 * @param {function} cb
 */
Sn4p.prototype.device = function(cb) {
    var self = this;
    var timestamp = Date.now();

    self._post(
        '/loq/all_updates',
        {
            'username'          : self.snapchatCredentials.username,
            'timestamp'         : timestamp,
            'type'              : 'android'
        },
        [
            self.authToken,
            timestamp
        ],
        false,
        cb
    );
};

/**
 *
 * @param {function} cb
 */
Sn4p.prototype.getUpdates = function(cb) {
    var self = this;
    var timestamp = Date.now();

    self._post(
        '/loq/all_updates',
        {
            'username'          : self.snapchatCredentials.username,
            'height'            : 1280,
            'width'             : 720,
            'max_video_height'  : 640,
            'max_video_width'   : 480,
            'timestamp'         : timestamp
        },
        [
            self.authToken,
            timestamp
        ],
        false,
        function(err, results) {
            if(err) return cb(err);

            // @todo Cache!

            cb(null, results);
        }
    );
};

/**
 *
 * @param {function} cb
 */
Sn4p.prototype.getConversations = function(cb) {
    var self = this;
    var timestamp = Date.now();

    this.getUpdates(function(err, updates) {
        var conversations = updates.conversations_response;

        if(conversations && conversations.length > 0) {
            var offset = null,
                last = conversations[conversations.length - 1];

            if(last.iter_token) {
                offset = last.iter_token;

                var usernameSum = crypto.createHash('md5');
                usernameSum.update(self.snapchatCredentials.username);
                var checksum = usernameSum.digest('hex');

                async.whilst(
                    function () {
                        return offset != null
                    },
                    function (nextWhilst) {
                        var timestamp = Date.now();

                        self._post(
                            '/loq/conversations',
                            {
                                'username': self.snapchatCredentials.username,
                                'checksum': checksum,
                                'offset': offset,
                                'features_map': '{}',
                                'timestamp': timestamp
                            },
                            [
                                self.authToken,
                                timestamp
                            ],
                            false,
                            function (err, results) {
                                if (err) return cb(err);

                                // Todo:
                                conversations = conversations.concat(results.conversations_response);
                                last = conversations[conversations.length - 1];
                                offset = last.iter_token;

                                cb(null, conversations);
                            }
                        );
                    },
                    cb
                );
            }
            else
                return cb(null, conversations);
        }
        else
            return cb();
    })
};

/**
 *
 * @param {function} cb
 */
Sn4p.prototype.getSnaps = function(cb) {
    this.getConversations(function(err, conversations) {
        if(err) return cb(err);

        var snaps = [];
        conversations.forEach(function(conversation) {
            var pendingReceivedSnaps = conversation.pending_received_snaps;
            pendingReceivedSnaps.forEach(function(snap) {
                var snapObj = {
                    id                  : snap.id,
                    mediaId             : snap.c_id || false,
                    mediaType           : snap.m,
                    time                : snap.t || false,
                    sender              : snap.sn || this.username,
                    recipient           : snap.rp || this.username,
                    status              : snap.st,
                    screenshotCount     : snap.c || 0,
                    sent                : snap.sts,
                    opened              : snap.ts,
                    broadcast           : snap.broadcast ||  {
                        url             : snap.broadcast_url,
                        action_text     : snap.broadcast_action_text,
                        hideTimer       : snap.broadcast_hide_timer
                    }
                };
                snaps.push(snapObj);
            });
        });

        cb(null, snaps);
    });
};

/**
 *
 * @param {Object|string} snap
 * @param {function} cb
 */
Sn4p.prototype.getMedia = function(snap, cb) {
    if(typeof snap == 'string')
        snap = { id: snap };

    var self = this;
    var timestamp = Date.now();

    var filename = 'temp/' + timestamp + '_' + snap.id,
        writeStream = fs.createWriteStream(filename);

    this._post(
        '/bq/blob',
        {
            'username'  : self.snapchatCredentials.username,
            'id'        : snap.id,
            'timestamp' : timestamp
        },
        [
            self.authToken,
            timestamp
        ],
        { stream: writeStream }
    );

    writeStream.on('error', function(err) { cb(err); });
    writeStream.on('finish', function(err) {
        snap.media = writeStream;
        cb(null, snap);
    });
};

///////////////////////////////////////
//
// PRIVATE METHODS

/**
 *
 * @param {string} first
 * @param {string} second
 * @returns {string}
 * @private
 */
Sn4p.prototype._hash = function(first, second) {
    first = SECRET + first;
    second = second + SECRET;

    var hashsum1 = crypto.createHash('sha256');
    hashsum1.update(first);
    var hash1 = hashsum1.digest('hex');

    var hashsum2 = crypto.createHash('sha256');
    hashsum2.update(second);
    var hash2 = hashsum2.digest('hex');

    var result = '';
    for(var i = 0; i < HASH_PATTERN.length; i++) {
        result += HASH_PATTERN.substr(i, 1) == '1' ? hash2.substr(i, 1) : hash1.substr(i, 1);
    }

    return result;
};

/**
 *
 * @param {string} email
 * @param {string} password
 * @return string
 * @private
 */
Sn4p.prototype._encryptPassword = function(email, password) {
    var googleDefaultPublicKey  = 'AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ==',
        keyBuffer               = new Buffer(googleDefaultPublicKey, 'base64');

    var halfString1     = keyBuffer.toString('hex').substr(8, 256),
        modulus         = bigint(halfString1, 16);

    var halfString2     = keyBuffer.toString('hex').substr(272, 6),
        exponent        = bigint(halfString2, 16);

    var shasum = crypto.createHash('sha1');
    shasum.update(keyBuffer.toString('binary'));

    var signature = '00' + shasum.digest('hex').substr(0, 8);

    var pem = ursa
        .createPublicKeyFromComponents(modulus.toBuffer(), exponent.toBuffer())
        .toPublicPem()
        .toString();

    var plain = email + '\x00' + password;

    var key         = new NodeRSA(pem),
        encrypted   = key.encrypt(plain, 'hex');

    var output          = new Buffer(signature + encrypted.toString('hex'), 'hex'),
        base64Output    = output.toString('base64');

    base64Output = base64Output.replace(/\+/g, '-');
    base64Output = base64Output.replace(/\//g, '_');

    return base64Output;
};

/**
 *
 * @param {string} endpoint
 * @param {Object} data
 * @param {Array} params
 * @param {object} reqOptions
 * @param {function} cb
 * @private
 */
Sn4p.prototype._post = function(endpoint, data, params, reqOptions, cb) {
    var options = {
        method      : 'POST',
        uri         : API_URL + endpoint,
        form        : data,
        //proxy       : 'http://127.0.0.1:8888'
    };

    // Add request token
    options.form.req_token = this._hash(params[0], params[1]);

    options.headers = {
        'User-Agent'                    : USER_AGENT,
        'Accept-Language'               : 'en',
        'Accept-Locale'                 : 'en_US',
        'X-Snapchat-Client-Auth-Token'  : 'Bearer'
    };

    // Add Beared
    if(endpoint == '/loq/login') {
        options.headers['X-Snapchat-Client-Auth-Token'] = 'Bearer ' + params[2];
        options.headers['X-Snapchat-Client-Auth']       = params[3];
        options.gzip                                    = true;
    }
    else {
        options.headers['X-Snapchat-Client-Auth-Token'] = 'Bearer ' + this.googleAuthToken;
    }

    var responseCb = function(err, res, body) {
        if(err) return cb(err);

        var data = {};
        try {
            data = JSON.parse(body);
        }
        catch(err) {
            return cb(new Error('Could not parse JSON from endpoint: ' + endpoint));
        }

        cb(null, data);
    };

    console.log(' --- POST: ' + options.uri);
    if(reqOptions.stream) {
        request(options).pipe(reqOptions.stream);
    }
    else
        request(options, responseCb);
};

/**
 *
 * @param {function} cb
 * @private
 */
Sn4p.prototype._getDeviceToken = function(cb) {
    var data = {
        timestamp: Date.now()
    };

    var params = [STATIC_TOKEN, data.timestamp];

    this._post('/loq/device_id', data, params, false, function(err, data) {
        if(err) return cb(err);

        if(!data || data.error == 1) return cb(new Error('Could not get device token!'));

        cb(null, data);
    });
};

/**
 *
 * @param {function} cb
 * @private
 */
Sn4p.prototype._getAuthToken = function(cb) {
    var encryptedPassword = this._encryptPassword(this.googleCredentials.email, this.googleCredentials.password);

    var options = {
        method      : 'POST',
        uri         : 'https://android.clients.google.com/auth',
        form        : {
            'device_country'                : 'us',
            'operatorCountry'               : 'us',
            'lang'                          : 'en_US',
            'sdk_version'                   : '19',
            'google_play_services_version'  : '7097038',
            'accountType'                   : 'HOSTED_OR_GOOGLE',
            'Email'                         : this.googleCredentials.email,
            'service'                       : 'audience:server:client_id:694893979329-l59f3phl42et9clpoo296d8raqoljl6p.apps.googleusercontent.com',
            'source'                        : 'android',
            'androidId'                     : '378c184c6070c26c',
            'app'                           : 'com.snapchat.android',
            'client_sig'                    : '49f6badb81d89a9e38d65de76f09355071bd67e7',
            'callerPkg'                     : 'com.snapchat.android',
            'callerSig'                     : '49f6badb81d89a9e38d65de76f09355071bd67e7',
            'EncryptedPasswd'               : encryptedPassword
        },
        headers: {
            'device'            : '378c184c6070c26c',
            'app'               : 'com.snapchat.android',
            'User-Agent'        : 'GoogleAuth/1.4 (mako JDQ39)'
        },
        gzip : true,
        //proxy : 'http://127.0.0.1:8888'
    };

    request(options, function(err, res, body) {
        if(err) return cb(err);

        var data = {};
        body.split('\n')
            .forEach(function(value) {
                var kv = value.split('=');
                var key = kv[0].charAt(0).toLowerCase() + kv[0].slice(1);
                return data[key] = kv[1];
            });

        if(!data.auth) return cb(new Error('Could not authenticate with google service'));

        cb(null, data);
    });
};

/**
 *
 * @param {number} timestamp
 * @param {function} cb
 * @private
 */
Sn4p.prototype._getAttestation = function(timestamp, cb) {
    var hashString = this.snapchatCredentials.username + '|' + this.snapchatCredentials.password + '|' + timestamp + '|/loq/login';

    var nonceSum = crypto.createHash('sha256');
    nonceSum.update(hashString);
    var nonce = nonceSum.digest('base64');

    var authentication = 'cp4craTcEr82Pdf5j8mwFKyb8FNZbcel',
        apkDigest      = 'JJShKOLH4YYjWZlJQ71A2dPTcmxbaMboyfo0nsKYayE';

    var options = {
        method      : 'POST',
        uri         : 'http://attest.casper.io/attestation',
        form        : {
            'nonce'           : nonce,
            'authentication'  : authentication,
            'apk_digest'      : apkDigest,
            'timestamp'       : timestamp
        },
        //proxy : 'http://127.0.0.1:8888'
    };

    request(options, function(err, res, body) {
        if(err) return cb(err);

        var data = JSON.parse(body);

        if(!data.signedAttestation) return cb(new Error('Could not get attestation from casper'));

        cb(null, data.signedAttestation);
    });
};


/**
 *
 * @param {number} timestamp
 * @param {function} cb
 * @private
 */
Sn4p.prototype._getClientAuthToken = function(timestamp, cb) {
    var options = {
        method      : 'POST',
        uri         : 'https://api.casper.io/security/login/signrequest',
        form        : {
            'username'      : this.snapchatCredentials.username,
            'password'      : this.snapchatCredentials.password,
            'timestamp'     : timestamp
        },
        //proxy : 'http://127.0.0.1:8888'
    };

    request(options, function(err, res, body) {
        if(err) return cb(err);

        var data = JSON.parse(body);

        if(!data.signature) return cb(new Error('Could not get auth token from casper'));

        cb(null, data.signature);
    });
};

///////////////////////////////////////////////////////////////////////////////
//
//
// EXPORTS
//

module.exports = Sn4p;