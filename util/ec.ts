import crypto from 'crypto';
import { ec as EC } from 'elliptic';

const DEFAULT_CURVE = 'secp256k1';
const ENCODE_REPLACEMENTS = { '+': '-', '/': '_', '=': '' };
const DECODE_REPLACEMENTS = { '-': '+', _: '/' };

type ReplacementsFrom = "+" | "=" | "/";
type ReplacementsTo = "-" | "_";

const b64urlEncode = (buf: Buffer) =>
  buf
    .toString('base64')
    .replace(/[+=/]/g, (match: ReplacementsFrom) => (ENCODE_REPLACEMENTS[match]));

const b64urlDecode = (s: string) =>
  Buffer.from(
    s.replace(/[-_]/g, (match: ReplacementsTo) => (DECODE_REPLACEMENTS[match])) +
      '='.repeat(3 - ((s.length - 1) % 4)),
    'base64'
  );

// is BN
// import BN from "bn.js"
// but .red says "red is a static property"
// which I'm not sure how to get around.
const bn2Buffer = (bn: any) => (bn.red ? bn.fromRed() : bn).toBuffer();

function messageHash(msg: string) {
  const hash = crypto.createHash('sha256');
  hash.update(msg);
  return hash.digest();
}

class Elliptic {
  key: EC.KeyPair;

  constructor(key: EC.KeyPair) {
    this.key = key;
  }

  privateKey() {
    return b64urlEncode(this.key.getPrivate().toBuffer());
  }

  publicKey() {
    const x = this.key.getPublic().getX();
    const y = this.key.getPublic().getY();
    return b64urlEncode(Buffer.concat([x, y].map(bn2Buffer)));
  }

  sign(msg: string) {
    let digest = messageHash(msg);
    let { r, s, recoveryParam } = this.key.sign(digest);
    return b64urlEncode(
      Buffer.from([recoveryParam, ...bn2Buffer(r), ...bn2Buffer(s)])
    ).substr(1); // Strip away the leading 'A'
  }

  verify(msg: string, signature: string) {
    try {
      let buf = b64urlDecode('A' + signature),
        nBytes = (buf.length - 1) >> 1;
      let r = buf.slice(1, 1 + nBytes),
        s = buf.slice(1 + nBytes);

      let digest = messageHash(msg);
      return this.key.verify(digest, { r, s });
    } catch (_) {
      return false;
    }
  }
}

export { b64urlEncode };

export const keyFromPublic = (pubKey: string, curve: string = DEFAULT_CURVE) => {
  let buf = b64urlDecode(pubKey),
    nBytes = buf.length >> 1;
  let x = buf.slice(0, nBytes),
    y = buf.slice(nBytes);

  let ec = new EC(curve);
  return new Elliptic(ec.keyFromPublic({ x: String(x), y: String(y) }));
};

export const keyFromSignature = (msg: string, signature: string, curve: string = DEFAULT_CURVE) => {
  let buf = b64urlDecode('A' + signature),
    nBytes = (buf.length - 1) >> 1;
  let recoveryParam = buf[0],
    r = buf.slice(1, 1 + nBytes),
    s = buf.slice(1 + nBytes);

  let ec = new EC(curve);
  let digest = messageHash(msg);
  let pubKey = ec.recoverPubKey(digest, { r, s }, recoveryParam);
  return new Elliptic(ec.keyFromPublic(pubKey));
};

export const keyFromPrivate = (key: string, curve: string = DEFAULT_CURVE) => {
  let ec = new EC(curve);
  return new Elliptic(ec.keyFromPrivate(b64urlDecode(key)));
};

export const generate = (curve: string = DEFAULT_CURVE) => {
  let ec = new EC(curve);
  return new Elliptic(ec.genKeyPair());
};
