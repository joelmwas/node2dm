#!/usr/bin/env node

var dgram = require('dgram')
  , util = require('util')
  , http = require('http')
  , https = require('https')
  , request = require('request')
  , querystring = require('querystring')
  , emitter = require('events').EventEmitter
  , config = require(userConfig())
  , fs = require('fs')
  , gcm = require('node-gcm')
  , net = require('net')

var pushType = {
    MPNS: 0,
    GCM: 1,
    C2DM: 2,
    NOKIA: 3
};

if (config.maxSockets) {
    http.Agent.defaultMaxSockets = config.maxSockets;
}

if (config.mpns) {
    try {
        var mpns = require('mpns');
    } catch (e) {
        config.mpns = false;
        log('mpns module is required for MPNS support.');
    }
}

if (config.syslog) {
    try {
        var syslog = require('node-syslog');
        syslog.init('node2dm', syslog.LOG_PID | syslog.LOG_ODELAY, syslog.LOG_DAEMON);
    } catch (e) {
        config.syslog = false;
        log('node-syslog is required for syslog support.');
    }
}

if (config.statsD) {
    try {
        var StatsD = require('node-statsd').StatsD;
        var host = config.statsD.host || "127.0.0.1";
        var port = config.statsD.port || 8125;
        var prefix = config.statsD.prefix || "";
        var suffix = config.statsD.suffix || "";
        var client = new StatsD(host, port, prefix, suffix);
    } catch (e) {
        config.statsD = false;
        log('node-statsd >= 0.0.4 is required for statsd support.');
    }
}

function userConfig() {
  return process.argv[2] ?
           process.argv[2].replace(/.js$/, '') :
           './config'
}

function log(msg) {
    if (config.syslog) {
        syslog.log(syslog.LOG_INFO, msg);
    } else {
        util.log('[' + config.port + '] ' + msg);
    }
}

function writeStat(stat) {
    if (config.statsD) {
        client.increment(stat, 1, config.statsD.samplingRate);
    }
}

var gUpperPortsUsed = 0;

function C2DMReceiver(config, c2dmConnection, gcmConnection, nokiaConnection) {

    this.GCMTokenPrefix = /^g\|(.*)$/;
    this.WPTokenPrefix = /^w\|(.*)$/;
    this.NokiaTokenPrefix = /^n\|(.*)$/;

    var self = this;

    this.server = dgram.createSocket('udp4', function (msg, rinfo) {
        var type = pushType.C2DM;
        msg = msg.toString(); // msg is a Buffer by default

        if (self.WPTokenPrefix.test(msg)) {
            type = pushType.MPNS;
            msg = msg.slice(2);
        } else if (self.NokiaTokenPrefix.test(msg)) {
            type = pushType.NOKIA;
            msg = msg.slice(2);
        } else if (self.GCMTokenPrefix.test(msg)) {
            type = pushType.GCM;
            msg = msg.slice(2);
        }

        switch (type) {
            case pushType.MPNS:
                // Message format: (entities url encoded)
                // pushURI:text1:text2:param
                var msgParts = msg.split(':').map(unescape);

                if (!msgParts.length) {
                    log("Invalid message");
                    return;
                }


                var pushURI = msgParts[0];
                var options = {
                    text1: msgParts[1],
                    text2: msgParts[2],
                    param: msgParts[3],
                }
                var callback = function (err, response) {
                    if (err && err.shouldDeleteChannel === true) {
                        writeStat("mpns.not_registered");
                    } else if (err) {
                        writeStat("mpns.error");
                        log(JSON.stringify(err));
                    } else {
                        writeStat("mpns.success");
                    }
                };

                if (config.httpProxy) {
                    options['proxy'] = config.httpProxy;
                }

                // Note that `param` needs to be a valid path, or the
                // notification will silently fail.
                writeStat("mpns.sent");
                mpns.sendToast(
                    pushURI,
                    options,
                    callback
                );

                break;
            case pushType.GCM:
            case pushType.C2DM:
            case pushType.NOKIA:
                // Message format:
                // token:collapseKey:notification
                var pattern = /^([^:]+):([^:]+):(.*)$/;
                var msgParts = pattern.exec(msg);
                if (!msgParts) {
                    log("Invalid message");
                    return;
                };

                var c2dmMessage = {
                    deviceToken: msgParts[1],
                    collapseKey: msgParts[2],
                    notification: msgParts[3]
                };

                switch (type) {
                    case pushType.GCM:
                        if (!gcmConnection) {
                            writeStat("gcm.no_gcm_server");
                            log("Can't send GCM message, no connection");
                            return;
                        }
                        gcmConnection.notifyDevice(c2dmMessage);
                        break;
                    case pushType.NOKIA:
                        if (!nokiaConnection) {
                            writeStat("gcm.no_nokia_server");
                            log("Can't send nokia message, no connection");
                            return;
                        }
                        nokiaConnection.notifyDevice(c2dmMessage);
                        break;
                    case pushType.C2DM:
                    default:
                        if (!c2dmConnection) {
                            writeStat("gcm.no_c2dm_server");
                            log("Can't send c2dm message, no connection");
                            return;
                        }
                        c2dmConnection.notifyDevice(c2dmMessage);
                        break;
                }

                break;
            default:
                log("Invalid push type.");
                break;
        }

    });
    this.server.bind(config.port || 8120);
    log("server is up");
}


function GCMConnection(config, apiKey, alternateHost, alternateEndpoint) {

    if (!apiKey) {
        return null;
    }

    this.sender = new gcm.Sender(config, apiKey, alternateEndpoint);
    var self = this;

    /*
     * Stats
     */
    var totalMessages = 0;
    var totalErrors = 0;
    var startupTime = Math.round(Date.now() / 1000);

    this.notifyDevice = function(pushData) {
        var message = new gcm.Message({
            collapseKey: pushData.collapseKey,
            data: {
                data: pushData.notification
            }
        });

        writeStat("gcm.sent");
        totalMessages++;
        self.sender.sendNoRetry(message, [pushData.deviceToken], function(err, result) {
            if (!err && result && result.failure === 0) {
                writeStat("gcm.success");
                return;
            }

            totalErrors++;
            if (result && result.failure > 0) {
                for (i = 0; i < result.results.length; i++) {
                    r = result.results[i];
                    if (r.error) {
                        if (r.error == "NotRegistered") {
                            writeStat("gcm.not_registered");
                            return;
                        } else if (r.error == "InvalidRegistration") {
                            writeStat("gcm.invalid_registration");
                            return;
                        } else {
                            log(r.error);
                            writeStat("gcm.unknown_google_error");
                            return;
                        }
                    }
                }
            }

            writeStat("gcm.error");
            log(err);
        });
    }

    this.debugServer = net.createServer(function(stream) {
        stream.setEncoding('ascii');

        stream.on('data', function(data) {
            var commandLine = data.trim().split(" ");
            var command = commandLine.shift();
            switch (command) {
                case "help":
                    stream.write("Commands: stats\n");
                    break;

                case "stats":
                    var now = Math.round(Date.now() / 1000);
                    var elapsed = now - startupTime;

                    stream.write("uptime: " + elapsed + " seconds\n");
                    stream.write("messages_sent: " + totalMessages + "\n");
                    stream.write("total_errors: " + totalErrors + "\n");

                    var memoryUsage = process.memoryUsage();
                    for (var property in memoryUsage) {
                        stream.write("memory_" + property + ": " + memoryUsage[property] + "\n");
                    }
                    stream.write("END\n\n");
                    break;

                case "quit":
                    stream.end();
                    break;

                default:
                    stream.write("Invalid command\n");
                    break;
            };
        });

    });
    this.debugServer.listen(config.debugServerPort + gUpperPortsUsed++ || config.port + 200 + gUpperPortsUsed++);
}



function C2DMConnection(config) {

    var self = this;

    this.c2dmServer = "https://apis.google.com/c2dm/send";
    this.loginServer = "https://www.google.com/accounts/ClientLogin";

    this.currentAuthorizationToken = null;
    this.authFails = 0;

    var blockedFromSending = false;
    var retryAfter = 0;
    var authInProgress = false;

    // if we exceed device quota for an ID,
    // place token in this group; it will
    // get cleared every 60 minutes
    this.rateLimitedTokens = {};

    // on fail, queue up here
    var pendingMessages = [];
    var totalMessages = 0;
    var totalErrors = 0;
    var authTokenTime = null;
    var startupTime = Math.round(new Date().getTime() / 1000);

    this.requeueMessage = function(message) {
        pendingMessages.push(message);
    }

    this.retryPendingMessages = function() {
        var numMessages = pendingMessages.length;
        for (var i = 0; i < numMessages; i++) {
            var message = pendingMessages.shift();
            self.submitMessage(message);
        };
    }

    // clear rate limited every hour
    setInterval(function() {
        self.rateLimitedTokens = {};
    }, 60 * 60 * 1000);

    // ensure log-in every 10 seconds
    function loginIfNotAuthenticated() {
        if (!self.currentAuthorizationToken) {
            self.authenticate();
        }
    }

    setInterval(function() {
        loginIfNotAuthenticated();
    }, 5 * 1000);

    this.on('loginComplete', function() {
        self.retryPendingMessages();
    });

    this.on('retryAfterExpired', function() {
        self.retryPendingMessages();
    });

    if (config.serverCallbackHost && config.serverCallbackPath) {
        this.on('badregistration', function(message) {
            // default to https
            var protocol = (config.serverCallbackProtocol == 'http' ? 'http' : 'https');
            var port = (config.serverCallbackPort || (config.serverCallbackProtocol == 'http' ? 80 : 443));
            var postBody = {
                device_token: message.deviceToken,
                message_body: message.notification,
                shared_secret: config.serverCallbackSharedSecret
            }

            var requestOptions = {
                url: protocol + '://' + config.serverCallbackHost + ':' + port + config.serverCallbackPath,
                form: postBody,
                timeout: config.timeout,
            }

            if (config.serverCallbackProxy) {
                requestOptions['proxy'] = config.serverCallbackProxy;
            }

            request.post(requestOptions, function(error, response, body) {
                if (error) {
                    writeStat('callback.error');
                    log('Callback error: ' + error);
                } else {
                    writeStat('callback.success');
                }
            });
        });
    }

    this.onError = function(message, err) {

        totalErrors++;
        var errMessage = err.match(/Error=(.+)$/);
        if (!errMessage) {
            log("Unknown error: " + err);
            writeStat("unknown_error");
        }
        var googleError = errMessage[1];
        switch (googleError) {
            case "QuotaExceeded":
                log("WARNING: Google Quota Exceeded");
                writeStat("quota_exceeded");
                break;

            case "DeviceQuotaExceeded":
                writeStat("device_quota_exceeded");
                self.rateLimitedTokens[message.deviceToken] = true;
                break;

            case "InvalidRegistration":
                writeStat("invalid_registration");
                self.emit("badregistration", message);
                break;

            case "NotRegistered":
                writeStat("not_registered");
                self.emit("badregistration", message);
                break;

            case "MessageTooBig":
                writeStat("message_too_big");
                log("ERROR: message too big");
                break;

            case "MissingRegistration":
                writeStat("missing_registration");
                log("ERROR: MissingRegistration");
                break;

            default:
                log("ERROR: Unknown Google Error: " + googleError);
                writeStat("unknown_google_error");
                break;

        }

    }

    this.sendRequest = function(message) {
        if (blockedFromSending) {
            self.requeueMessage(message);
            return;
        }
        if (self.rateLimitedTokens[message.deviceToken]) {
            log("not sending; this token has been rate limited");
            return;
        }

        var c2dmPostBody = {
            registration_id: message.deviceToken,
            collapse_key: message.collapseKey,
            "data.data": message.notification,
        }

        var requestOptions =  {
            url: self.c2dmServer,
            form: c2dmPostBody,
            encoding: 'utf-8',
            headers: {
                // Google send a bad SSL cert which doesn't cover android.apis.google.com
                // Use apis.google.com in the URL to validate the cert, and then override
                // the Host header to get the right vhost
                'Host': 'android.apis.google.com',
                'Authorization': 'GoogleLogin auth=' + self.currentAuthorizationToken
            },
            timeout: config.timeout,
        };

        if (config.httpProxy) {
            requestOptions['proxy'] = config.httpProxy;
        }

        request.post(requestOptions, function(error, response, body) {
            if (error) {
                totalErrors++;
                log(error);
                writeStat("failure");
            } else if (response.statusCode == 401) {
                // we need to reauthenticate
                self.currentAuthorizationToken = null;
                // requeue message
                self.requeueMessage(message);
            } else if (response.statusCode == 503) {
                retryAfter = parseInt(response.headers['Retry-After'], 10) || 10;
                blockedFromSending = true;
                self.requeueMessage(message);
                setTimeout(function() {
                    blockedFromSending = false;
                    self.emit('retryAfterExpired');
                }, retryAfter * 1000);
            } else if (response.statusCode == 200) {
                writeStat("success");
                var returnedID = body.match(/id=/);
                if (!returnedID) {
                    self.onError(message, body);
                }
            }
        });

    }

    this.submitMessage = function(message) {
        if (self.currentAuthorizationToken) {
            self.sendRequest(message);
            writeStat("sent");
        } else {
            self.requeueMessage(message);
            writeStat("requeued");
        }
    }

    this.notifyDevice = function(message) {
        totalMessages++;
        self.submitMessage(message);
    };

    this.authenticate = function() {
        if (authInProgress) {
            return;
        }
        if (self.authFails > 10) {
            log("Could not auth after 10 attempts!");
            process.exit(1);
        }

        authInProgress = true;

        var loginBody = {
            "accountType": "HOSTED_OR_GOOGLE",
            "Email": config.username,
            "Passwd": config.password,
            "service": "ac2dm",
            "source": config.source
        }

        var login_options = {
            url: self.loginServer,
            form: loginBody,
            encoding: 'utf-8',
            timeout: config.timeout,
        }

        if (config.httpProxy) {
            login_options['proxy'] = config.httpProxy;
        }

        request.post(login_options, function(error, response, body) {
            if (error) {
                log(error);
                authInProgress = false;
            } else {
                var token = body.match(/Auth=(.+)[$|\n]/);
                if (token) {
                    self.currentAuthorizationToken = token[1];
                    authTokenTime = Math.round(new Date().getTime() / 1000);
                    self.authFails = 0;
                    self.emit('loginComplete');
                } else {
                    log("Auth fail; body: " + body);
                    if (body.match(/CaptchaToken/)) {
                        log("Must auth with captcha; exiting");
                        process.exit(1);
                    }
                    self.authFails++;
                }
                log('auth token: ' + self.currentAuthorizationToken);
                authInProgress = false;
            }
        });
    };

    this.debugServer = net.createServer(function(stream) {
        stream.setEncoding('ascii');

        stream.on('data', function(data) {
            var commandLine = data.trim().split(" ");
            var command = commandLine.shift();
            switch (command) {
                case "help":
                    stream.write("Commands: stats authtoken\n");
                    break;

                case "authtoken":
                    if (self.currentAuthorizationToken) {
                        stream.write("token: " + self.currentAuthorizationToken + "\n");
                    }
                    stream.write("END\n\n");
                    break;

                case "stats":
                    var now = Math.round(new Date().getTime() / 1000);
                    var elapsed = now - startupTime;

                    var tokenAge = now - authTokenTime;

                    stream.write("uptime: " + elapsed + " seconds\n");
                    stream.write("messages_sent: " + totalMessages + "\n");
                    stream.write("messages_in_queue: " + pendingMessages.length + "\n");
                    stream.write("backing_off: " + (blockedFromSending ? "true" : "false") + "\n");
                    stream.write("total_errors: " + totalErrors + "\n");
                    stream.write("rate_limited_tokens: " + Object.keys(self.rateLimitedTokens).length + "\n");
                    var loggedInStatus = (self.currentAuthorizationToken ? "true" :  "false");
                    stream.write("logged_in_to_c2dm: " + loggedInStatus + "\n");
                    if (self.currentAuthorizationToken) {
                        stream.write("token_age: " + tokenAge + " seconds\n");
                    }

                    var memoryUsage = process.memoryUsage();
                    for (var property in memoryUsage) {
                        stream.write("memory_" + property + ": " + memoryUsage[property] + "\n");
                    }
                    stream.write("END\n\n");
                    break;

                case "quit":
                    stream.end();
                    break;

                default:
                    stream.write("Invalid command\n");
                    break;
            };
        });

    });
    this.debugServer.listen(config.debugServerPort + gUpperPortsUsed++ || config.port + 100 + gUpperPortsUsed++);
}

util.inherits(C2DMConnection, emitter);


// check for a lock file; if it's there,
// don't start until removed
fs.stat('quota.lock', function(err, stats) {
    if (!err) {
        log("Can't start; quota.lock present");
        process.exit(1);
    }

    var c2DMConnection = null;
    var gcmConnection = null;
    var nokiaConnection = null;
    if (config.username && config.password) {
        c2DMConnection = new C2DMConnection(config);
    }
    if (config.gcmAPIKey) {
        gcmConnection = new GCMConnection(config, config.gcmAPIKey);
    }
    if (config.nokiaAPIKey) {
        nokiaConnection = new GCMConnection(
            config,
            config.nokiaAPIKey,
            "https://nnapi.ovi.com/nnapi/2.0/send");
    }

    var receiver = new C2DMReceiver(
        config,
        c2DMConnection,
        gcmConnection,
        nokiaConnection);
});

