import crypto from 'crypto';
import hmacFP from './HmacFP';
import is from 'is';
import moment from 'moment';
import random_engine from 'random-js';

const random =  random_engine();
const C1_VERSION = 0x80000702;
const RFC2409_PRIME_1024 = Buffer.from(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
            "FFFFFFFFFFFFFFFF", "hex");

const C1_LENGTH = 1536
const C1_HEADER_LENGTH = 8
const C1_PAYLOAD_LENGTH = C1_LENGTH - C1_HEADER_LENGTH

const KEY_POINTER_OFFSET = 1532
const KEY_LENGTH = 128
const KEY_CHUNK_LENGTH = C1_PAYLOAD_LENGTH / 2 - KEY_LENGTH - 4
const KEY_CHUNK_OFFSET = C1_HEADER_LENGTH + C1_PAYLOAD_LENGTH / 2  /* 772 */

const DIGEST_POINTER_OFFSET = 8
const DIGEST_LENGTH = 32
const DIGEST_CHUNK_LENGTH = C1_PAYLOAD_LENGTH / 2 - DIGEST_LENGTH - 4
const DIGEST_CHUNK_OFFSET = C1_HEADER_LENGTH + 4 /* 12 */


export default class C1 {
  static fromBuffer(buf) {
    const c1 = new C1();
    c1._buf = buf;

    return c1;
  }

  static create() {
    const c1 = new C1();
    c1._buf = crypto.randomBytes(1536);

    return c1;
  }

  getVersion() {
    return C1_VERSION;
  }

  getTime() {
    return this._buf.readUInt32BE(0);
  }

  getDigestOffset() {
    const digest_pointer = this._readPointerAt(DIGEST_POINTER_OFFSET)
    return DIGEST_CHUNK_OFFSET  + (digest_pointer % DIGEST_CHUNK_LENGTH)
  }

  getDigest() {
    const digest_offset = this.getDigestOffset();

    return this._buf.slice(digest_offset, DIGEST_LENGTH + digest_offset);
  }

  getKeyOffset() {
    const key_pointer = this._readPointerAt(KEY_POINTER_OFFSET)
    return KEY_CHUNK_OFFSET + (key_pointer % KEY_CHUNK_LENGTH)
  }

  getkey() {
    const key_offset = this.getKeyOffset();

    return this._buf.slice(key_offset, KEY_LENGTH + key_offset);
  }

  getJoinPart() {
    const digest_offset = this.getDigestOffset();

    return Buffer.concat([
      this._buf.slice(0, digest_offset),
      this._buf.slice(DIGEST_LENGTH + digest_offset)
    ]);
  }

  encode() {
    this._buf.writeUInt32BE(moment.unix(), 0);
    this._buf.writeUInt32BE(C1_VERSION, 4);

    this._dh = crypto.createDiffieHellman(RFC2409_PRIME_1024);

    const key_offset = random.integer(0, 764 - 128 - 4);
    this._buf.writeUInt32BE(key_offset, 1532);
    const key = this._dh.generateKeys();
    key.copy(this._buf, 772 + key_offset);

    const digest_offset = random.integer(0, 764 - 4 - 32);
    this._buf.writeUInt32BE(digest_offset, 8);
    const digest = hmacFP(this.getJoinPart());
    digest.copy(this._buf, 12 + digest_offset);

    return this._buf;
  }

  validate() {
    const digest_offset = this.getDigestOffset();
    if (!is.within(digest_offset, 0, 764 - 4 - 32)) {
      return false;
    }

    const key_offset = this.getKeyOffset();
    if (!is.within(key_offset, 0, 764 - 4 - 32)) {
      return false;
    }

    return true;
  }

  _readPointerAt(start) {
      let index = 0
      for (let i = start; i < start + 4; ++i) {
        index += this._buf.readUInt8(i)
      }
      return index
  }
}
