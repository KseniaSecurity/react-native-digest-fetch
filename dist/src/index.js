'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _extends2 = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

exports.setNextNonceCount = setNextNonceCount;
exports.padStart = padStart;
exports.getNextNonceCount = getNextNonceCount;
exports.omitNullValues = omitNullValues;
exports.quoteIfRelevant = quoteIfRelevant;
exports.getDigestHeaderValue = getDigestHeaderValue;
exports.fetchAuth = fetchAuth;
exports.getHeaders = getHeaders;
exports.default = fetchWithDigest;

var _cryptoJs = require('crypto-js');

var _cryptoJs2 = _interopRequireDefault(_cryptoJs);

var _url = require('url');

var _url2 = _interopRequireDefault(_url);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// If the user's environment already includes fetch, we want to use it
if (typeof window !== 'undefined' && typeof window.fetch === 'undefined') {
  window.fetch = require('node-fetch').default;
}
if (typeof global !== 'undefined' && typeof global.fetch === 'undefined') {
  global.fetch = require('node-fetch').default;
}

function keys(object) {
  var result = [];
  for (var key in object) {
    if (object.hasOwnProperty(key)) {
      result.push(key);
    }
  }
  return result;
}

function pick(object, whitelist) {
  var result = {};
  var keylength = whitelist.length;
  for (var keyIndex = 0; keyIndex < keylength; keyIndex += 1) {
    result[whitelist[keyIndex]] = object[whitelist[keyIndex]];
  }
  return result;
}

/**
 * Pass the server's www-authenticate header
 * @param {*} digestChallenge
 */
function getDigestChallengeParts(digestChallenge) {
  var prefix = 'Digest ';
  var challenge = digestChallenge.substr(digestChallenge.indexOf(prefix) + prefix.length);
  var challengeArray = challenge.split(',');

  return challengeArray.reduce(function (result, challengeItem) {
    var splitPart = challengeItem.match(/^\s*?([a-zA-Z0-0]+)=("?(.*)"?|MD5|MD5-sess|token|TRUE|FALSE)\s*?$/);

    if (splitPart.length > 2) {
      result[splitPart[1]] = splitPart[2].replace(/\"/g, '');
    }

    return result;
  }, {});
}

function setNextNonceCount(nextId) {
  getNextNonceCount.nonceCount = nextId;
}

function padStart(string, length, paddingCharacter) {
  if (string.length < length) {
    return paddingCharacter.repeat(length - string.length) + string;
  }
  return string;
}

/**
 * Incremented nonce used in responses to server challenges
 */
function getNextNonceCount() {
  if (typeof getNextNonceCount.nonceCount === 'undefined') {
    getNextNonceCount.nonceCount = 0;
  }
  getNextNonceCount.nonceCount = ((getNextNonceCount.nonceCount || 0) + 1) % 100000000;
  return padStart('' + getNextNonceCount.nonceCount, 8, '0');
}

function omitNullValues(data) {
  return keys(data).reduce(function (result, key) {
    if (data[key] !== null || data[key] !== 'undefined') result[key] = data[key];
    return result;
  }, {});
}

/**
 * Both the nc and key parameters are expected to be sent without quotes
 * @param {*} object
 * @param {*} key
 */
function quoteIfRelevant(object, key) {
  return key === 'nc' || key === 'qop' ? '' + object[key] : '"' + object[key] + '"';
}

/**
 * Get the authorization header value `Authorization: Digest XXXXX`, we want XXXXX
 * @param {*} digestChallenge
 * @param {*} param1
 */
function getDigestHeaderValue(digestChallenge, _ref) {
  var url = _ref.url,
      method = _ref.method,
      headers = _ref.headers,
      username = _ref.username,
      password = _ref.password;

  var parsed = _url2.default.parse(url);
  var path = parsed.path;
  var challengeParts = getDigestChallengeParts(digestChallenge);

  var authHash = _cryptoJs2.default.MD5([username, challengeParts.realm, password].join(':'));
  var pathHash = _cryptoJs2.default.MD5([method, path].join(':'));

  var cnonce = null;
  var nonce_count = null;
  if (typeof challengeParts.qop === 'string') {
    cnonce = _cryptoJs2.default.MD5(Math.random().toString(36)).toString(_cryptoJs2.default.enc.Hex).substr(0, 8);
    nonce_count = getNextNonceCount();
  }

  var responseParams = [authHash.toString(_cryptoJs2.default.enc.Hex), challengeParts.nonce].concat(cnonce ? [nonce_count, cnonce] : []).concat([challengeParts.qop, pathHash.toString(_cryptoJs2.default.enc.Hex)]);

  var authParams = omitNullValues(_extends2({}, pick(challengeParts, ['realm', 'nonce', 'opaque', 'qop']), {
    username: username,
    uri: path,
    algorithm: 'MD5',
    response: _cryptoJs2.default.MD5(responseParams.join(':')).toString(_cryptoJs2.default.enc.Hex),
    nc: nonce_count,
    cnonce: cnonce
  }));

  var paramArray = keys(authParams).reduce(function (result, key) {
    if (typeof authParams[key] !== 'function') {
      result.push(key + '=' + quoteIfRelevant(authParams, key));
    }

    return result;
  }, []);

  return paramArray.join(',');
}

function fetchAuth(url, parameters) {
  return fetch(url, _extends({}, parameters));
}

function getHeaders(url, parameters, initialResults) {
  var headers = parameters.headers,
      method = parameters.method,
      body = parameters.body,
      username = parameters.username,
      password = parameters.password,
      responseType = parameters.responseType;
  if (initialResults && initialResults.headers && initialResults.headers.get('www-authenticate')) {
    var digestHeader = getDigestHeaderValue(initialResults.headers.get('www-authenticate'), {
      url: url,
      responseType: responseType,
      method: method,
      headers: headers,
      username: username,
      password: password
    });
    return _extends({}, headers, {
      Authorization: 'Digest ' + digestHeader
    });
  }
}

/**
 * Exact same parameters as fetch
 * @param {string} url
 * @param {object} parameters
 */
function fetchWithDigest(url, parameters) {
  var headers = parameters.headers,
      method = parameters.method,
      body = parameters.body,
      username = parameters.username,
      password = parameters.password;

  return fetch(url, _extends2({}, parameters)).then(function (initialResults) {
    if (initialResults && initialResults.headers && initialResults.headers.get('www-authenticate')) {
      var digestHeader = getDigestHeaderValue(initialResults.headers.get('www-authenticate'), { url: url, method: method, headers: headers, username: username, password: password });
      return fetch(url, _extends2({}, parameters, { headers: _extends2({}, headers, { Authorization: 'Digest ' + digestHeader }) }));
    }

    return initialResults;
  });
}