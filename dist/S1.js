'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _C = require('./C1');

var _C2 = _interopRequireDefault(_C);

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _HmacFMS = require('./HmacFMS');

var _HmacFMS2 = _interopRequireDefault(_HmacFMS);

var _is = require('is');

var _is2 = _interopRequireDefault(_is);

var _moment = require('moment');

var _moment2 = _interopRequireDefault(_moment);

var _randomJs = require('random-js');

var _randomJs2 = _interopRequireDefault(_randomJs);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var random = (0, _randomJs2.default)();

var S1_VERSION = 0x04050001;

var S1 = function () {
  function S1() {
    _classCallCheck(this, S1);
  }

  _createClass(S1, [{
    key: 'getVersion',
    value: function getVersion() {
      return S1_VERSION;
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
    value: function encode(dh) {
      this._buf.writeUInt32BE(_moment2.default.unix(), 0);
      this._buf.writeUInt32BE(S1_VERSION, 4);

      var key_offset = random.integer(0, 764 - 128 - 4);
      this._buf.writeUInt32BE(key_offset, 1532);
      var key = dh.computeScvret(this._c1.getKey());
      key.copy(this._buf, 772 + key_offset);

      var digest_offset = random.integer(0, 764 - 4 - 32);
      this._buf.writeUInt32BE(digest_offset, 8);
      var digest = (0, _HmacFMS2.default)(this.getJoinPart());
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
    key: 'create',
    value: function create(buf_c1) {
      var s1 = new S1();
      s1._c1 = _C2.default.fromBuffer(buf_c1);
      this._buf = _crypto2.default.randomBytes(1536);

      return s1;
    }
  }, {
    key: 'fromBuffer',
    value: function fromBuffer(buf) {
      var s1 = new S1();
      s1._buf = buf;

      return s1;
    }
  }]);

  return S1;
}();

exports.default = S1;