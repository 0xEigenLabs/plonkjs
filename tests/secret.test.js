const { expect } = require("chai");
const path = require("path");
const fs = require("fs");

const { prover } = require("../");

describe.skip("Secret prove and verify test", function() {
  this.timeout(5000000);
  it("Should return true when proof is correct", async function() {
    // let basePath = __dirname;
    let basePath = "/tmp/secret";
    let circuit_file = path.join(basePath, "main_update_state.r1cs");
    let circuit_file_content = fs.readFileSync(circuit_file);
    let wtns = path.join(basePath, "witness.wtns");
    let wtns_content = fs.readFileSync(wtns);
    let srs_monomial_form = path.join(basePath, "setup_2^18.key");
    let srs_monomial_form_content = fs.readFileSync(srs_monomial_form);

    let start = new Date().getTime();
    console.log(start);

    let proof = prover.prove(
      circuit_file_content.toJSON().data,
      wtns_content.toJSON().data,
      srs_monomial_form_content.toJSON().data,
      "keccak"
    );

    let end = new Date().getTime();
    console.log(`prove cost: ${(end - start)/1000} s`);
    // generate verify key
    let vk = prover.export_verification_key(
      srs_monomial_form_content.toJSON().data,
      circuit_file_content.toJSON().data
    );

    let end2 = new Date().getTime();
    console.log(`export vk cost: ${(end2 - end)/1000} s`);

    // verify
    let verify_ok = prover.verify(
      Array.from(vk.vk_bin),
      Array.from(proof.proof_bin),
      "keccak"
    )
    let end3 = new Date().getTime();
    console.log(`verify cost: ${(end3 - end2)/1000} s`);
    expect(verify_ok).eq(true)
  });
});
