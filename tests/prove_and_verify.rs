#![cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(all(test, target_arch = "wasm32"))]
extern crate wasm_bindgen_test;

#[cfg(all(test, target_arch = "wasm32"))]
use wasm_bindgen_test::*;

#[macro_use]
use plonkjs;
use plonkjs::log;

#[wasm_bindgen]
extern "C" {
    type Buffer;
}
#[wasm_bindgen(module = "/tests/read_file.js")]
extern "C" {
    #[wasm_bindgen(catch)]
    fn read_file(path: &str) -> Result<Buffer, JsValue>;
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[test]
fn test_prove_and_verify() {
    let circuit_file = read_file("circuit").unwrap();

    let wtns = read_file("wtns").unwrap();
    let srs_monomial_form = read_file("key").unwrap();

    let proof = plonkjs::prove(
        JsValue::from(circuit_file.clone()),
        JsValue::from(wtns),
        JsValue::from(srs_monomial_form.clone()),
        String::from("keccak"),
    );

    let vk = plonkjs::export_verification_key(
        JsValue::from(srs_monomial_form),
        JsValue::from(circuit_file),
    );

    let verified_ok = plonkjs::verify(
        JsValue::from_serde(&vk.vk_bin).unwrap(),
        JsValue::from_serde(&proof.proof_bin).unwrap(),
        String::from("keccak"));
    assert!(verified_ok);
}
