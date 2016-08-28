'use strict';

const string = str => typeof str === 'string';
const ascii = /^[\x00-\x7F]+$/;
const hex = /^[0-9A-F]+$/i;
const notBase64 = /[^A-Z0-9+\/=]/i;

module.exports = {
  'buffer' : Buffer.isBuffer,
  'ascii'  : (str) => string(str) && ascii.test(str),
  'hex'    : (str) => string(str) && hex.test(str),
  'utf8'   : (str) => string(str) && str === (new Buffer(str, 'utf8')).toString('utf8'),
  'base64' : (str) => {
      if (!string(str))
        return false;
      const len = str.length;
      if (!len || len % 4 !== 0 || notBase64.test(str)) {
        return false;
      }
      const firstPaddingChar = str.indexOf('=');
      return firstPaddingChar === -1 ||
        firstPaddingChar === len - 1 ||
        (firstPaddingChar === len - 2 && str[len - 1] === '=');
  }
};
