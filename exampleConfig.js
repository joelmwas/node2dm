/*
 * Required variables
 *
 * username (Google account ID)
 * password (Google account password)
 * source (Google source, like 'com-your-app')
 * port (port to bind to)
 * address (address to bind to)
 * statsD {host: (statsD host), port: (statsD port), prefix/suffix: (stat name prefix/suffix), sampling: sampling rate)
 * debugServerPort (port to bind for stats / debug server)
 * debugServeraddress (address to bind for stats / debug server)
 * serverCallbackHost / serverCallbackPort / serverCallbackPath / serverCallbackSharedSecret /
 * serverCallbackProtocol
 * (if specified, will be used to send a POST back to a service in order to handle bad tokens)
 *
 */
 
  var config = {}
  config.port =  8120;
  config.address= "127.0.0.1";
  config.syslog = false;
  config.statsD = {host: "127.0.0.1", port: 8125, prefix: "stats.node2dm.", suffix: "", sampling: 0.1};
  module.exports = config;

