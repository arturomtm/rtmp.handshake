'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _HmacFMS = require('./HmacFMS');

var _HmacFMS2 = _interopRequireDefault(_HmacFMS);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var C2 = function () {
  function C2() {
    _classCallCheck(this, C2);
  }

  _createClass(C2, [{
    key: 'getRandom',
    value: function getRandom() {
      return this._buf.slice(0, 1504);
    }
  }, {
    key: 'getDigest',
    value: function getDigest() {
      return this._buf.slice(1504);
    }
  }, {
    key: 'encode',
    value: function encode() {
      var hmac = _crypto2.default.createHmac('sha256', (0, _HmacFMS2.default)(this._s1.getDigest()));
      hmac.update(this.getRandom());
      var digest = hmac.digest();
      digest.copy(this._buf, 1504);

      return this._buf;
    }
  }, {
    key: 'validate',
    value: function validate(s1) {
      var hmac = _crypto2.default.createHmac((0, _HmacFMS2.default)(s1.getDigest()));
      hmac.update(this.getRandom());
      var digest = hmac.digest();

      return Buffer.compare(digest, this.getDigest()) === 0;
    }
  }], [{
    key: 'create',
    value: function create(s1) {
      var c2 = new C2();
      c2._buf = _crypto2.default.randomBytes(1536);
      c2._s1 = s1;

      return c2;
    }
  }, {
    key: 'fromBuffer',
    value: function fromBuffer(buf) {
      var c2 = new C2();
      c2._buf = buf;

      return c2;
    }
  }]);

  return C2;
}();

exports.default = C2;