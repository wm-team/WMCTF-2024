import crypto from 'node:crypto';

const XOR_KETBUF = Buffer.from([0x11, 0x45, 0x14]);

function xorBuffer(databuf, keybuf) {
    let res = Buffer.alloc(databuf.length);
    for (let i = 0; i < databuf.length; i++) {
        res[i] = databuf[i] ^ keybuf[i % keybuf.length];
    }
    return res;
}

function tobase64(buf, removePadding = true) {
    return Buffer.from(buf).toString('base64').replace(/=/g, '');
}

function frombase64(str) {
    return Buffer.from(str, 'base64');
}

// base64(data) . base64(salt ^ xorkey + hmac_sha256(data ^ xorkey + salt))
function sign(json, secret) {
    let data_buf = Buffer.from(JSON.stringify(json));
    let xor_buf = Buffer.from(XOR_KETBUF);
    let salt_buf = crypto.randomBytes(16);

    let hash = crypto.createHmac('sha256', secret);
    let encdata = Buffer.concat([xorBuffer(Buffer.from(data_buf), xor_buf), salt_buf]);
    hash.update(encdata);
    let sig_buf = hash.digest();
    let token = tobase64(data_buf) + '.' + tobase64(Buffer.concat([xorBuffer(salt_buf, xor_buf), sig_buf]));
    return token;
}

function verify(token, secret) {
    let [enc_data, enc_p2] = token.split('.');
    let data_buf = frombase64(enc_data);
    let p2_buf = frombase64(enc_p2);
    let hash_bytelen = 32;
    let salt_buf = xorBuffer(p2_buf.subarray(0, p2_buf.length - hash_bytelen), XOR_KETBUF);
    let sig_buf = p2_buf.subarray(p2_buf.length - hash_bytelen);
    let hash = crypto.createHmac('sha256', secret);
    hash.update(Buffer.concat([xorBuffer(data_buf, XOR_KETBUF), salt_buf]));
    let expected_sig_buf = hash.digest();
    if (Buffer.compare(sig_buf, expected_sig_buf) !== 0) {
        return null;
    } else {
        return JSON.parse(data_buf);
    }
}

export default class TokenManager {
    constructor(secret) {
        this.sign = (json) => sign(json, secret);
        this.verify = (token) => verify(token, secret);
        this.data = (token) => JSON.parse(frombase64(token.split('.')[0]).toString());
    }
}
