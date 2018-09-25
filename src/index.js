import cryptojs from 'crypto-js';
import URL from 'url';

// If the user's environment already includes fetch, we want to use it
if (typeof window !== 'undefined' && typeof window.fetch === 'undefined') {
  window.fetch = require('node-fetch').default;
}
if (typeof global !== 'undefined' && typeof global.fetch === 'undefined') {
  global.fetch = require('node-fetch').default;
}

function keys(object) {
  const result = [];
  for (let key in object) {
    if (object.hasOwnProperty(key)) {
      result.push(key);
    }
  }
  return result;
}

function pick(object, whitelist) {
  const result = {};
  const keylength = whitelist.length;
  for (let keyIndex = 0; keyIndex < keylength; keyIndex += 1) {
    result[whitelist[keyIndex]] = object[whitelist[keyIndex]];
  }
  return result;
}

/**
 * Pass the server's www-authenticate header
 * @param {*} digestChallenge
 */
function getDigestChallengeParts(digestChallenge) {
  const prefix = 'Digest ';
  const challenge = digestChallenge.substr(digestChallenge.indexOf(prefix) + prefix.length);
  const challengeArray = challenge.split(',');

  return challengeArray.reduce((result, challengeItem) => {
    const splitPart = challengeItem.match(/^\s*?([a-zA-Z0-0]+)=("?(.*)"?|MD5|MD5-sess|token|TRUE|FALSE)\s*?$/);

    if (splitPart.length > 2) {
      result[splitPart[1]] = splitPart[2].replace(/\"/g, '');
    }

    return result;
  }, {});
}

export function setNextNonceCount(nextId) {
  getNextNonceCount.nonceCount = nextId;
}

export function padStart(string, length, paddingCharacter) {
  if (string.length < length) {
    return paddingCharacter.repeat(length - string.length) + string;
  }
  return string;
}

/**
 * Incremented nonce used in responses to server challenges
 */
export function getNextNonceCount() {
  if (typeof getNextNonceCount.nonceCount === 'undefined') {
    getNextNonceCount.nonceCount = 0;
  }
  getNextNonceCount.nonceCount = (((getNextNonceCount.nonceCount || 0) + 1) % 100000000);
  return padStart('' + getNextNonceCount.nonceCount, 8, '0');
}

export function omitNullValues(data) {
  return keys(data).reduce((result, key) => {
    if (data[key] !== null || data[key] !== 'undefined') result[key] = data[key];
    return result;
  }, {});
}

/**
 * Both the nc and key parameters are expected to be sent without quotes
 * @param {*} object
 * @param {*} key
 */
export function quoteIfRelevant(object, key) {
  return (key === 'nc' || key === 'qop') ? `${object[key]}` : `"${object[key]}"`;
}

/**
 * Get the authorization header value `Authorization: Digest XXXXX`, we want XXXXX
 * @param {*} digestChallenge
 * @param {*} param1
 */
export function getDigestHeaderValue(digestChallenge, { url, method, headers, username, password }) {
  const parsed = URL.parse(url);
  const path = parsed.path;
  const challengeParts = getDigestChallengeParts(digestChallenge);

  const authHash = cryptojs.MD5([username, challengeParts.realm, password].join(':'));
  const pathHash = cryptojs.MD5([method, path].join(':'));

  let cnonce = null;
  let nonce_count = null;
  if (typeof challengeParts.qop === 'string') {
    cnonce = cryptojs.MD5(Math.random().toString(36)).toString(cryptojs.enc.Hex).substr(0, 8);
    nonce_count = getNextNonceCount();
  }

  const responseParams = [authHash.toString(cryptojs.enc.Hex), challengeParts.nonce]
    .concat(cnonce ? [nonce_count, cnonce] : [])
    .concat([challengeParts.qop, pathHash.toString(cryptojs.enc.Hex)]);

  const authParams = omitNullValues({
    ...pick(challengeParts, ['realm', 'nonce', 'qop']),
    username: username,
    uri: path,
    algorithm: 'MD5',
    response: cryptojs.MD5(responseParams.join(':')).toString(cryptojs.enc.Hex),
    nc: nonce_count,
    cnonce,
  });

  const paramArray = keys(authParams).reduce((result, key) => {
    if (typeof (authParams[key]) !== 'function') {
      result.push(`${key}=${quoteIfRelevant(authParams, key)}`);
    }

    return result;
  }, []);

  return paramArray.join(',');
}

export function fetchAuth(url, parameters) {
  return fetch(url, { ...parameters })
}

export function getHeaders(url, parameters, initialResults) {
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
    return {
      ...parameters, headers: {
        Authorization: 'Digest ' + digestHeader
      }
    }
  }
}

/**
 * Exact same parameters as fetch
 * @param {string} url
 * @param {object} parameters
 */
export default function fetchWithDigest(url, parameters) {
  const { headers, method, body, username, password } = parameters
  return fetch(url, { ...parameters }).then(initialResults => {
    if (initialResults && initialResults.headers && initialResults.headers.get('www-authenticate')) {
      const digestHeader = getDigestHeaderValue(initialResults.headers.get('www-authenticate'), { url, method, headers, username, password });
      return fetch(url, { ...parameters, headers: { ...headers, Authorization: `Digest ${digestHeader}` } });
    }

    return initialResults;
  });
}
