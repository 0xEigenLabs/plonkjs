#![cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::circom_circuit::CircomCircuit;
use crate::console_log;
use crate::log;
use crate::plonk;
use crate::reader;
use std::io::{BufReader, BufWriter, Cursor};

use crate::bellman_ce::{
    kate_commitment::{Crs, CrsForMonomialForm},
    pairing::bn256::Bn256,
    plonk::{
        better_cs::cs::PlonkCsWidth4WithNextStepParams,
        better_cs::keys::{Proof, VerificationKey},
    },
    Field, PrimeFieldRepr,
};

#[wasm_bindgen(getter_with_clone)]
pub struct ProofJS {
    pub proof_bin: Vec<u8>,
    pub proof_json: String,
    pub public_json: String,
}

#[wasm_bindgen(getter_with_clone)]
pub struct VKJS {
    pub vk_bin: Vec<u8>,
}

#[wasm_bindgen]
pub fn prove(
    circuit_js_objs: JsValue,
    witness_js_objs: JsValue,
    srs_monomial_form_js_objs: JsValue,
    transcript: String,
) -> Result<ProofJS, JsValue> {
    let circuit_value: Vec<u8> = circuit_js_objs
        .into_serde()
        .map_err(|e| JsValue::from(e.to_string()))?;
    let r1cs_reader = BufReader::new(Cursor::new(circuit_value));
    let (r1cs, _) = reader::load_r1cs_from_bin(r1cs_reader);

    let witness_value: Vec<u8> = witness_js_objs
        .into_serde()
        .map_err(|e| JsValue::from(e.to_string()))?;
    let witness_reader = BufReader::new(Cursor::new(witness_value));
    let witness =
        reader::load_witness_from_bin_reader::<Bn256, BufReader<Cursor<Vec<u8>>>>(witness_reader)
            .map_err(|e| JsValue::from(e.to_string()))?;

    let circuit = CircomCircuit {
        r1cs: r1cs,
        witness: Some(witness),
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };
    let srs_monomial_form_value: Vec<u8> = srs_monomial_form_js_objs
        .into_serde()
        .map_err(|e| JsValue::from(e.to_string()))?;
    let mut srs_monomial_form_reader = BufReader::new(Cursor::new(srs_monomial_form_value));
    let srs_monomial_form = Crs::<Bn256, CrsForMonomialForm>::read(&mut srs_monomial_form_reader)
        .map_err(|e| JsValue::from(e.to_string()))?;

    let setup = crate::plonk::SetupForProver::prepare_setup_for_prover(
        circuit.clone(),
        srs_monomial_form,
        None,
    )
    .map_err(|e| JsValue::from(e.to_string()))?;

    let proof = setup
        .prove(circuit, &transcript)
        .map_err(|e| JsValue::from(e.to_string()))?;
    let mut contents = BufWriter::new(Vec::new());
    proof
        .write(&mut contents)
        .map_err(|e| JsValue::from(e.to_string()))?;

    let (inputs, serialized_proof) = bellman_vk_codegen::serialize_proof(&proof);
    let ser_proof_str = serde_json::to_string_pretty(&serialized_proof)
        .map_err(|e| JsValue::from(e.to_string()))?;
    let ser_inputs_str =
        serde_json::to_string_pretty(&inputs).map_err(|e| JsValue::from(e.to_string()))?;

    Ok(ProofJS {
        proof_bin: contents.into_inner().unwrap(),
        proof_json: ser_proof_str,
        public_json: ser_inputs_str,
    })
}

#[wasm_bindgen]
pub fn export_verification_key(
    srs_monomial_form_js_objs: JsValue,
    circuit_js_objs: JsValue,
) -> Result<VKJS, JsValue> {
    let circuit_value: Vec<u8> = circuit_js_objs
        .into_serde()
        .map_err(|e| JsValue::from(e.to_string()))?;

    let r1cs_reader = BufReader::new(Cursor::new(circuit_value));
    let (r1cs, _) = reader::load_r1cs_from_bin(r1cs_reader);

    let circuit = CircomCircuit {
        r1cs: r1cs,
        witness: None,
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    let srs_monomial_form_value: Vec<u8> = srs_monomial_form_js_objs
        .into_serde()
        .map_err(|e| JsValue::from(e.to_string()))?;

    let mut srs_monomial_form_reader = BufReader::new(Cursor::new(srs_monomial_form_value));
    let srs_monomial_form = Crs::<Bn256, CrsForMonomialForm>::read(&mut srs_monomial_form_reader)
        .map_err(|e| JsValue::from(e.to_string()))?;

    let setup = plonk::SetupForProver::prepare_setup_for_prover(
        circuit,
        //reader::load_key_monomial_form(srs_monomial_form),
        srs_monomial_form,
        None,
    )
    .map_err(|e| JsValue::from(e.to_string()))?;
    let vk = setup
        .make_verification_key()
        .map_err(|e| JsValue::from(e.to_string()))?;

    let mut contents = BufWriter::new(Vec::new());
    vk.write(&mut contents)
        .map_err(|e| JsValue::from(e.to_string()))?;

    Ok(VKJS {
        vk_bin: contents.into_inner().unwrap(),
    })
}

#[wasm_bindgen]
pub fn verify(
    vk_file_js_objs: JsValue,
    proof_bin_js_objs: JsValue,
    transcript: String,
) -> Result<bool, JsValue> {
    let vk_file_value: Vec<u8> = vk_file_js_objs
        .into_serde()
        .map_err(|e| JsValue::from(e.to_string()))?;
    let mut reader = BufReader::new(Cursor::new(vk_file_value));
    let vk = VerificationKey::<Bn256, PlonkCsWidth4WithNextStepParams>::read(&mut reader)
        .map_err(|e| JsValue::from(e.to_string()))?;

    let proof_value: Vec<u8> = proof_bin_js_objs
        .into_serde()
        .map_err(|e| JsValue::from(e.to_string()))?;
    let proof_reader = BufReader::new(Cursor::new(proof_value));
    let proof = Proof::<Bn256, PlonkCsWidth4WithNextStepParams>::read(proof_reader)
        .map_err(|e| JsValue::from(e.to_string()))?;

    let ok = plonk::verify(&vk, &proof, &transcript).map_err(|e| JsValue::from(e.to_string()))?;
    Ok(ok)
}
