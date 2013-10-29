/*
 * Required variables
 * For C2DM:
 * username (Google account ID)
 * password (Google account password)
 * source (Google source, like 'com-your-app')
 *
 * For GCM:
 *
 * gcmAPIKey
 *
 *
 * port (port to bind to)
 * address (address to bind to)
 * statsD {host: (statsD host), port: (statsD port), prefix/suffix: (stat name prefix/suffix), samplingRate: sampling rate)
 * debugServerPort (port to bind for c2dm stats / debug server)
 * debugServeraddress (address to bind for c2dm  stats / debug server)
 * gcmDebugServerPort (port to bind for gcm stats / debug server)
 * gcmServerAddress (address to bind for gcm  stats / debug server)
 * serverCallbackHost / serverCallbackPort / serverCallbackPath / serverCallbackSharedSecret /
 * serverCallbackProtocol
 * (if specified, will be used to send a POST back to a service in order to handle bad tokens)
 *
 */

  var config = {}
  config.port =  8120;
  config.address= "127.0.0.1";
  config.syslog = false;
  config.mpns = false;
  config.statsD = {host: "127.0.0.1", port: 8125, prefix: "stats.node2dm.", suffix: "", samplingRate: 0.1};
  module.exports = config;

