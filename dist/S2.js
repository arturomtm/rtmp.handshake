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

var S2 = function () {
  function S2() {
    _classCallCheck(this, S2);
  }

  _createClass(S2, [{
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
      var hmac = _crypto2.default.createHmac('sha256', (0, _HmacFMS2.default)(this._c1.getDigest()));
      hmac.update(this.getRandom());
      var digest = hmac.digest();
      digest.copy(this._buf, 1504);

      return this._buf;
    }
  }, {
    key: 'validate',
    value: function validate(c1) {
      var hmac = _crypto2.default.createHmac((0, _HmacFMS2.default)(c1.getDigest()));
      hmac.update(this.getRandom());
      var digest = hmac.digest();

      return Buffer.compare(digest, this.getDigest()) === 0;
    }
  }], [{
    key: 'create',
    value: function create(c1) {
      var s2 = new S2();
      s2._buf = _crypto2.default.randomBytes(1536);
      s2._c1 = c1;

      return s2;
    }
  }, {
    key: 'fromBuffer',
    value: function fromBuffer(buf) {
      var s2 = new S2();
      s2._buf = buf;

      return s2;
    }
  }]);

  return S2;
}();

exports.default = S2;