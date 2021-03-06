import crypto from 'crypto';
import hmacFMS from './HmacFMS';

export default class S2 {
  static create(c1) {
    const s2 = new S2();
    s2._buf = crypto.randomBytes(1536);
    s2._c1 = c1;

    return s2;
  }

  static fromBuffer(buf) {
    const s2 = new S2();
    s2._buf = buf;

    return s2;
  }

  getRandom() {
    return this._buf.slice(0, 1504);
  }

  getDigest() {
    return this._buf.slice(1504);
  }

  encode() {
    const hmac = crypto.createHmac('sha256', hmacFMS(this._c1.getDigest()));
    hmac.update(this.getRandom());
    const digest = hmac.digest();
    digest.copy(this._buf, 1504);

    return this._buf;
  }

  validate(c1) {
    const hmac = crypto.createHmac(hmacFMS(c1.getDigest()));
    hmac.update(this.getRandom());
    const digest = hmac.digest();

    return Buffer.compare(digest, this.getDigest()) === 0;
  }
}
