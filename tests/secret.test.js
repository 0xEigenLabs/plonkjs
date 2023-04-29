const { expect } = require("chai");
const path = require("path");
const fs = require("fs");

const {prover} = require("../");

describe("Secret prove and verify test", function() {
  this.timeout(5000000);
  it("Should return true when proof is correct", async function() {
    //let basePath = __dirname;
    let basePath = "/tmp/secret";
    let circuit_file = path.join(basePath, "main_update_state.r1cs");
    let circuit_file_content = fs.readFileSync(circuit_file);
    let wtns = path.join(basePath, "witness.wtns");
    let wtns_content = fs.readFileSync(wtns);
    let srs_monomial_form = path.join(basePath, "setup_2^18.key");
    let srs_monomial_form_content = fs.readFileSync(srs_monomial_form);
    let proof = prover.prove(
      circuit_file_content.toJSON().data,
      wtns_content.toJSON().data,
      srs_monomial_form_content.toJSON().data,
      "keccak"
    );

    // generate verify key
    let vk = prover.export_verification_key(
      srs_monomial_form_content.toJSON().data,
      circuit_file_content.toJSON().data
    );

    // verify
    let verify_ok = prover.verify(
      Array.from(vk.vk_bin),
      Array.from(proof.proof_bin),
      "keccak"
    )
    console.log(verify_ok);
    expect(verify_ok).eq(true)

  });
});
