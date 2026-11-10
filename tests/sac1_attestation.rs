use sac::v1::{
    CanonicalObject, Error, ObjectHash,
    attestation::parse_cose_sign1,
    cbor::{self, Value},
};

fn map(entries: Vec<(Value, Value)>) -> Value {
    let mut entries: Vec<_> = entries
        .into_iter()
        .map(|(key, value)| sac::cbor::MapEntry {
            key_bytes: cbor::encode(&key),
            key,
            value,
        })
        .collect();
    entries.sort_by(|a, b| a.key_bytes.cmp(&b.key_bytes));
    Value::Map(entries)
}
fn protected() -> Value {
    map(vec![(Value::Uint(1), Value::NInt(18))])
}
fn payload() -> Value {
    Value::Array(vec![
        Value::Text("sac.snapshot.v1".into()),
        Value::Text("release".into()),
        Value::Bytes(vec![7; 32]),
    ])
}
fn encode(headers: Value, unprotected: Value, payload: Value, signature: Vec<u8>) -> Vec<u8> {
    let mut bytes = vec![0xd2];
    bytes.extend(cbor::encode(&Value::Array(vec![
        Value::Bytes(cbor::encode(&headers)),
        unprotected,
        payload,
        Value::Bytes(signature),
    ])));
    bytes
}
fn valid() -> Vec<u8> {
    encode(
        protected(),
        map(vec![]),
        Value::Bytes(cbor::encode(&payload())),
        vec![0; 64],
    )
}
fn replace(encoded: &[u8], index: usize, value: Value) -> Vec<u8> {
    let Value::Array(mut fields) = cbor::decode(&encoded[1..]).unwrap() else {
        panic!()
    };
    fields[index] = value;
    let mut out = vec![0xd2];
    out.extend(cbor::encode(&Value::Array(fields)));
    out
}

#[test]
fn structural_parse_exposes_signed_subject_without_claiming_a_signature_is_valid() {
    let parsed = parse_cose_sign1(&valid()).unwrap();
    assert_eq!(parsed.purpose(), "release");
    assert_eq!(parsed.snapshot(), ObjectHash([7; 32]));
    assert_eq!(parsed.key_id(), None);
    assert_eq!(parsed.signature(), &[0; 64]);
    assert_eq!(
        parsed.signature_input(),
        cbor::encode(&Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(cbor::encode(&protected())),
            Value::Bytes(vec![]),
            Value::Bytes(cbor::encode(&payload()))
        ]))
    );
    let bytes = encode(
        map(vec![
            (Value::Uint(1), Value::NInt(18)),
            (Value::Uint(4), Value::Bytes(b"caller-key-id".to_vec())),
        ]),
        map(vec![]),
        Value::Bytes(cbor::encode(&payload())),
        vec![0; 64],
    );
    assert_eq!(
        parse_cose_sign1(&bytes).unwrap().key_id(),
        Some(b"caller-key-id".as_slice())
    );
}

#[test]
fn malformed_tag_shape_payload_and_signature_reject() {
    let baseline = valid();
    assert!(parse_cose_sign1(&baseline[1..]).is_err());
    let mut wrong_tag = baseline.clone();
    wrong_tag[0] = 0xd1;
    assert!(parse_cose_sign1(&wrong_tag).is_err());
    let mut nonminimal = vec![0xd8, 18];
    nonminimal.extend(&baseline[1..]);
    assert!(parse_cose_sign1(&nonminimal).is_err());
    let mut extra = baseline.clone();
    extra.push(0);
    assert!(parse_cose_sign1(&extra).is_err());
    for signature in [vec![0; 63], vec![0; 65]] {
        assert!(parse_cose_sign1(&replace(&baseline, 3, Value::Bytes(signature))).is_err());
    }
    for value in [
        Value::Null,
        Value::Text("detached".into()),
        Value::Bytes(cbor::encode(&Value::Array(vec![]))),
    ] {
        assert!(parse_cose_sign1(&replace(&baseline, 2, value)).is_err());
    }
    let Value::Array(mut fields) = payload() else {
        panic!()
    };
    for (index, value) in [
        (0, Value::Text("other.domain".into())),
        (1, Value::Uint(1)),
        (2, Value::Bytes(vec![7; 31])),
    ] {
        let old = std::mem::replace(&mut fields[index], value);
        assert!(
            parse_cose_sign1(&replace(
                &baseline,
                2,
                Value::Bytes(cbor::encode(&Value::Array(fields.clone())))
            ))
            .is_err()
        );
        fields[index] = old;
    }
    let mut trailing = cbor::encode(&payload());
    trailing.push(0);
    assert!(parse_cose_sign1(&replace(&baseline, 2, Value::Bytes(trailing))).is_err());
    let mut oversized = baseline;
    oversized.resize(1025, 0);
    assert!(matches!(parse_cose_sign1(&oversized), Err(Error::Limit(_))));
}

#[test]
fn exact_protected_recipe_and_text_bounds_are_enforced() {
    let body = Value::Bytes(cbor::encode(&payload()));
    assert!(
        parse_cose_sign1(&encode(map(vec![]), protected(), body.clone(), vec![0; 64])).is_err()
    );
    assert!(matches!(
        parse_cose_sign1(&encode(
            map(vec![(Value::Uint(1), Value::NInt(7))]),
            map(vec![]),
            body.clone(),
            vec![0; 64]
        )),
        Err(Error::Unsupported(_))
    ));
    for unprotected in [
        protected(),
        map(vec![(Value::Uint(4), Value::Bytes(vec![1]))]),
        map(vec![(Value::Uint(42), Value::Bool(true))]),
    ] {
        assert!(
            parse_cose_sign1(&encode(protected(), unprotected, body.clone(), vec![0; 64])).is_err()
        );
    }
    for kid in [
        Value::Bytes(vec![]),
        Value::Bytes(vec![1; 129]),
        Value::Text("wrong type".into()),
    ] {
        let headers = map(vec![
            (Value::Uint(1), Value::NInt(18)),
            (Value::Uint(4), kid),
        ]);
        assert!(
            parse_cose_sign1(&encode(headers, map(vec![]), body.clone(), vec![0; 64])).is_err()
        );
    }
    for label in [
        Value::Uint(2),
        Value::Uint(42),
        Value::Text("extension".into()),
    ] {
        let headers = map(vec![
            (Value::Uint(1), Value::NInt(18)),
            (label, Value::Bool(true)),
        ]);
        assert!(
            parse_cose_sign1(&encode(headers, map(vec![]), body.clone(), vec![0; 64])).is_err()
        );
    }
    for purpose in ["".to_string(), "x".repeat(257), "é".repeat(129)] {
        let subject = Value::Array(vec![
            Value::Text("sac.snapshot.v1".into()),
            Value::Text(purpose),
            Value::Bytes(vec![7; 32]),
        ]);
        assert!(
            parse_cose_sign1(&encode(
                protected(),
                map(vec![]),
                Value::Bytes(cbor::encode(&subject)),
                vec![0; 64]
            ))
            .is_err()
        );
    }
    let subject = Value::Array(vec![
        Value::Text("sac.snapshot.v1".into()),
        Value::Text("é".repeat(128)),
        Value::Bytes(vec![7; 32]),
    ]);
    assert!(
        parse_cose_sign1(&encode(
            protected(),
            map(vec![]),
            Value::Bytes(cbor::encode(&subject)),
            vec![0; 64]
        ))
        .is_ok()
    );
}

#[test]
fn catalogue_assessment_keeps_optional_inner_failures_independent() {
    let mut object = CanonicalObject {
        kind: 9,
        version: 1,
        bytes: cbor::encode(&Value::Array(vec![Value::Bytes(valid())])),
        children: vec![],
    };
    sac::v1::validate_core_object(&object).unwrap();
    object.bytes = cbor::encode(&Value::Array(vec![Value::Bytes(b"not COSE".to_vec())]));
    sac::v1::validate_core_object(&object).unwrap();
    let unsupported = encode(
        map(vec![(Value::Uint(1), Value::NInt(7))]),
        map(vec![]),
        Value::Bytes(cbor::encode(&payload())),
        vec![0; 64],
    );
    object.bytes = cbor::encode(&Value::Array(vec![
        Value::Bytes(valid()),
        Value::Bytes(b"not COSE".to_vec()),
        Value::Bytes(unsupported),
    ]));
    let outcomes = sac::v1::attestation::assess_catalogue(&object, ObjectHash([7; 32])).unwrap();
    use sac::v1::attestation::StructureStatus::*;
    assert_eq!(
        outcomes.iter().map(|o| o.structure).collect::<Vec<_>>(),
        vec![ValidStructure, Invalid, Unsupported]
    );
    assert!(outcomes.iter().all(|o| !o.signature_accepted));
    assert_eq!(
        sac::v1::attestation::assess_catalogue(&object, ObjectHash([8; 32])).unwrap()[0].structure,
        Invalid
    );
}

#[cfg(feature = "trust")]
#[test]
fn caller_key_verification_authenticates_the_exact_cose_signature_input() {
    use ed25519_dalek::{Signer, SigningKey};
    let signing = SigningKey::from_bytes(&[3; 32]);
    let initial = valid();
    let parsed = parse_cose_sign1(&initial).unwrap();
    let signature = signing.sign(&parsed.signature_input());
    let signed = replace(&initial, 3, Value::Bytes(signature.to_bytes().to_vec()));
    let parsed = parse_cose_sign1(&signed).unwrap();
    assert!(
        parsed
            .verify_ed25519(&signing.verifying_key().to_bytes())
            .unwrap()
    );
    assert!(
        !parsed
            .verify_ed25519(&SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes())
            .unwrap()
    );
    let changed = Value::Array(vec![
        Value::Text("sac.snapshot.v1".into()),
        Value::Text("other purpose".into()),
        Value::Bytes(vec![7; 32]),
    ]);
    let changed =
        parse_cose_sign1(&replace(&signed, 2, Value::Bytes(cbor::encode(&changed)))).unwrap();
    assert!(
        !changed
            .verify_ed25519(&signing.verifying_key().to_bytes())
            .unwrap()
    );
    let wrong_aad = cbor::encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(cbor::encode(&protected())),
        Value::Bytes(vec![1]),
        Value::Bytes(cbor::encode(&payload())),
    ]));
    let wrong = replace(
        &initial,
        3,
        Value::Bytes(signing.sign(&wrong_aad).to_bytes().to_vec()),
    );
    assert!(
        !parse_cose_sign1(&wrong)
            .unwrap()
            .verify_ed25519(&signing.verifying_key().to_bytes())
            .unwrap()
    );
}
