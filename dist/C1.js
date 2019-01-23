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
      return this._buf.readUInt32BE(8);
    }
  }, {
    key: 'getDigest',
    value: function getDigest() {
      var digest_offset = this.getDigestOffset();

      return this._buf.slice(12 + digest_offset, 44 + digest_offset);
    }
  }, {
    key: 'getKeyOffset',
    value: function getKeyOffset() {
      return this._buf.readUInt32BE(1532);
    }
  }, {
    key: 'getkey',
    value: function getkey() {
      var key_offset = this.getKeyOffset();

      return this._buf.slice(772 + key_offset, 900 + key_offset);
    }
  }, {
    key: 'getJoinPart',
    value: function getJoinPart() {
      var digest_offset = this.getDigestOffset();

      return Buffer.concat([this._buf.slice(0, 12 + digest_offset), this._buf.slice(44 + digest_offset)]);
    }
  }, {
    key: 'encode',
    value: function encode() {
      this._buf.writeUInt32BE(_moment2.default.unix(), 0);
      this._buf.writeUInt32BE(C1_VERSION, 4);

      this._dh = _crypto2.default.createDiffieHellman(RFC2409_PRIME_1024);

      var key_offset = random.integer(0, 764 - 128 - 4);
      this._buf.writeUInt32BE(key_offset, 1532);
      var key = this._dh.generateKeys();
      key.copy(this._buf, 772 + key_offset);

      var digest_offset = random.integer(0, 764 - 4 - 32);
      this._buf.writeUInt32BE(digest_offset, 8);
      var digest = (0, _HmacFP2.default)(this.getJoinPart());
      digest.copy(this._buf, 12 + digest_offset);

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