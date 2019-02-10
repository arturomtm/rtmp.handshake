'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _HmacFP = require('./HmacFP');

var _HmacFP2 = _interopRequireDefault(_HmacFP);

var _is = require('is');

var _is2 = _interopRequireDefault(_is);

var _moment = require('moment');

var _moment2 = _interopRequireDefault(_moment);

var _randomJs = require('random-js');

var _randomJs2 = _interopRequireDefault(_randomJs);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var random = (0, _randomJs2.default)();
var C1_VERSION = 0x80000702;
var RFC2409_PRIME_1024 = Buffer.from("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" + "FFFFFFFFFFFFFFFF", "hex");

var C1_LENGTH = 1536;
var C1_HEADER_LENGTH = 8;
var C1_PAYLOAD_LENGTH = C1_LENGTH - C1_HEADER_LENGTH;

var KEY_POINTER_OFFSET = 1532;
var KEY_LENGTH = 128;
var KEY_CHUNK_LENGTH = C1_PAYLOAD_LENGTH / 2 - KEY_LENGTH - 4;
var KEY_CHUNK_OFFSET = C1_HEADER_LENGTH + C1_PAYLOAD_LENGTH / 2; /* 772 */

var DIGEST_POINTER_OFFSET = 8;
var DIGEST_LENGTH = 32;
var DIGEST_CHUNK_LENGTH = C1_PAYLOAD_LENGTH / 2 - DIGEST_LENGTH - 4;
var DIGEST_CHUNK_OFFSET = C1_HEADER_LENGTH + 4; /* 12 */

var C1 = function () {
  function C1() {
    _classCallCheck(this, C1);
  }

  _createClass(C1, [{
    key: 'getVersion',
    value: function getVersion() {
      return C1_VERSION;
    }
  }, {
    key: 'getTime',
    value: function getTime() {
      return this._buf.readUInt32BE(0);
    }
  }, {
    key: 'getDigestOffset',
    value: function getDigestOffset() {
      var digest_pointer = this._readPointerAt(DIGEST_POINTER_OFFSET);
      return DIGEST_CHUNK_OFFSET + digest_pointer % DIGEST_CHUNK_LENGTH;
    }
  }, {
    key: 'getDigest',
    value: function getDigest() {
      var digest_offset = this.getDigestOffset();

      return this._buf.slice(digest_offset, DIGEST_LENGTH + digest_offset);
    }
  }, {
    key: 'getKeyOffset',
    value: function getKeyOffset() {
      var key_pointer = this._readPointerAt(KEY_POINTER_OFFSET);
      return KEY_CHUNK_OFFSET + key_pointer % KEY_CHUNK_LENGTH;
    }
  }, {
    key: 'getkey',
    value: function getkey() {
      var key_offset = this.getKeyOffset();

      return this._buf.slice(key_offset, KEY_LENGTH + key_offset);
    }
  }, {
    key: 'getJoinPart',
    value: function getJoinPart() {
      var digest_offset = this.getDigestOffset();

      return Buffer.concat([this._buf.slice(0, digest_offset), this._buf.slice(DIGEST_LENGTH + digest_offset)]);
    }
  }, {
    key: 'encode',
    value: function encode() {
      this._buf.writeUInt32BE(_moment2.default.unix(), 0);
      this._buf.writeUInt32BE(C1_VERSION, 4);

      this._dh = _crypto2.default.createDiffieHellman(RFC2409_PRIME_1024);

      var key = this._dh.generateKeys();
      var keyOffset = this.getKeyOffset();
      key.copy(this._buf, keyOffset);

      var digest = (0, _HmacFP2.default)(this.getJoinPart());
      var digestOffset = this.getDigestOffset();
      digest.copy(this._buf, digestOffset);

      return this._buf;
    }
  }, {
    key: 'validate',
    value: function validate() {
      var digest_offset = this.getDigestOffset();
      if (!_is2.default.within(digest_offset, 0, 764 - 4 - 32)) {
        return false;
      }

      var key_offset = this.getKeyOffset();
      if (!_is2.default.within(key_offset, 0, 764 - 4 - 32)) {
        return false;
      }

      return true;
    }
  }, {
    key: '_readPointerAt',
    value: function _readPointerAt(start) {
      var index = 0;
      for (var i = start; i < start + 4; ++i) {
        index += this._buf.readUInt8(i);
      }
      return index;
    }
  }], [{
    key: 'fromBuffer',
    value: function fromBuffer(buf) {
      var c1 = new C1();
      c1._buf = buf;

      return c1;
    }
  }, {
    key: 'create',
    value: function create() {
      var c1 = new C1();
      c1._buf = _crypto2.default.randomBytes(1536);

      return c1;
    }
  }]);

  return C1;
}();

exports.default = C1;