const ffj = require("ffjavascript");
const buildEddsa = require("circomlibjs").buildEddsa;
const buildPoseidon = require("circomlibjs").buildPoseidon;
const buildBabyjub = require("circomlibjs").buildBabyjub;
const TwistedElGamal = require("./twisted_elgamal.js");
const fs = require("fs");
const crypto = require("crypto");
var path = require('path');

function buff2hex(buff) {
    function i2hex(i) {
      return ('0' + i.toString(16)).slice(-2);
    }
    return Array.from(buff).map(i2hex).join('');
}

const fromHexString = hexString =>
  new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

const toHexString = bytes =>
  bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');

module.exports = class ZKTX {
  constructor(circuit_path) {
    this.eddsa = undefined;
    this.Scalar = ffj.Scalar;
    this.poseidon = undefined;
    this.F = undefined;
    this.twistedElGamal = undefined;
    this.circuit_path = circuit_path;
  }

  async initialize() {
    this.eddsa = await buildEddsa();
    this.poseidon = await buildPoseidon();
    this.babyJub = await buildBabyjub();
    this.F = this.poseidon.F;
    this.twistedElGamal = new TwistedElGamal(this.babyJub, this.eddsa);
  }

  // amount: BigInt
  // sender: address
  // receiver: address
  // nonce: BigInt
  async createTX(amount, senderPrvKey, nonce, tokenType, receiverPubKey, c_l_old, c_r_old) {
    // make input data
    const F = this.babyJub.F;
    const buf = crypto.randomBytes(32);
    const r_h = ffj.Scalar.shr(ffj.Scalar.fromRprLE(buf, 0, 32), 3);
    let H = this.babyJub.mulPointEscalar(this.babyJub.Base8, r_h)
    let senderPubKey = this.twistedElGamal.pubkey(senderPrvKey);
    const ct = this.twistedElGamal.encrypt(senderPubKey, H, amount);
    const r = ct.r;
    const c_l = ct.c_l;
    const c_r = ct.c_r;
    // make signature
    const pSenderPubKey = this.babyJub.packPoint(senderPubKey);
    const pReceiverPubKey = this.babyJub.packPoint(receiverPubKey);
    const msg = this.poseidon([pSenderPubKey, pReceiverPubKey, nonce, tokenType]);
    const signature = this.eddsa.signPoseidon(senderPubKey, msg);
    // make proof
    const proof = await this.createTxProof(senderPubKey, receiverPubKey, H, amount, r, c_l, c_r, c_l_old, c_r_old, msg, signature);

    return {
      signature: signature,
      proof: proof,
      c_l: c_l,
      c_r: c_r,
    }
  }

  // TODO: fetch zkey and wasm from eigen server
  async createTxProof(senderPubKey, receiverPubKey, H, amount, r, c_l, c_r, c_l_old, c_r_old, msg, signature) {
    const F = this.babyJub.F;
    let wasm = path.join(this.circuit_path, "zktx.wasm");
    let zkey = path.join(__dirname, "../circuits/setup_2^15.key");
    const wc = require(path.join(this.circuit_path, "witness_calculator"));

    /*
    var reader = new FileReader();     // FileReader object
    reader.readAsArrayBuffer(wasm);
    var buffer = new Uint8Array(reader.result, 0, reader.result.byteLength);eader.readAsArrayBuffer(wasm);    // perform reading
    */
    const buffer = fs.readFileSync(wasm);

    const witnessCalculator = await wc(buffer);

    console.log("createProof", c_l_old, c_l);

    let c_l_new = this.babyJub.addPoint(
      c_l_old,
      c_l,
    )

    let c_r_new = this.babyJub.addPoint(
      c_r_old,
      c_r,
    );


    const input = {
      senderPubkey: [
        F.toString(senderPubKey[0]),
        F.toString(senderPubKey[1])
      ],
      receiverPubkey: [
        F.toString(receiverPubKey[0]),
        F.toString(receiverPubKey[1])
      ],
      amount: amount,
      Max: 2**31,
      r: r,
      H: [F.toString(H[0]),  F.toString(H[1])],
      C_S: [
        [F.toString(c_l_old[0]), F.toString(c_l_old[1])],
        [F.toString(c_r_old[0]), F.toString(c_r_old[1])]
      ],
      C_S_NEW: [
        [F.toString(c_l_new[0]), F.toString(c_l_new[1])],
        [F.toString(c_r_new[0]), F.toString(c_r_new[1])]
      ]
    }

    const witnessBuffer = await witnessCalculator.calculateWTNSBin(
        input,
        0
    );
    console.log("begin to prove");
    /*
    const { proof, publicSignals } = await snarkjs.plonk.prove(zkey, witnessBuffer);
    const res = await snarkjs.plonk.exportSolidityCallData(proof, "");
    return res.substring(0, res.length - 3);
    */
    //TODO
  }
}
