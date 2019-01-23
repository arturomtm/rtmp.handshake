"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var C0 = function () {
  function C0() {
    _classCallCheck(this, C0);
  }

  _createClass(C0, [{
    key: "encode",
    value: function encode() {
      return this._buf;
    }
  }, {
    key: "validate",
    value: function validate() {
      if (Buffer.compare(C0.DATA, this._buf) !== 0) {
        return false;
      }

      return true;
    }
  }], [{
    key: "create",
    value: function create() {
      var c0 = new C0();
      c0._buf = C0.DATA;

      return c0;
    }
  }, {
    key: "fromBuffer",
    value: function fromBuffer(buf) {
      var c0 = new C0();
      c0._buf = buf;

      return c0;
    }
  }]);

  return C0;
}();

C0.DATA = Buffer.from([0x03]);
exports.default = C0;