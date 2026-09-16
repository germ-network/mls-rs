// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

//! The swift-mls format-2 export fixture for the deployed PQ suite: a real
//! `Group` on `CipherSuite::ML_KEM_768`, exported through
//! `export_for_swift`, self-checked, and written to
//! `../mls-rs/test_data/swift-migration-mlkem768.json` for the swift-mls
//! RESTORE+DECRYPT validation.
//!
//! This file lives HERE, not in mls-rs, because only this crate's ML-KEM
//! provider produces the 96-byte CryptoKit `integrityCheckedRepresentation`
//! secret form the snapshot carries (AWS-LC's 2400-byte form is refused by
//! the exporter). The bridge needs the Swift toolchain, so the whole file is
//! compiled only on Apple targets -- `cargo test --all-features --workspace`
//! on Linux compiles it to nothing.

#![cfg(all(feature = "post-quantum", any(target_os = "macos", target_os = "ios")))]

use mls_rs::{
    client,
    client_builder::{BaseConfig, ClientBuilder, WithCryptoProvider, WithIdentityProvider},
    group::ReceivedMessage,
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    time::MlsTime,
    CipherSuite, MlsMessage,
};
use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};
use mls_rs_crypto_cryptokit::CryptoKitMlKemProvider;

use serde::Serialize;

/// `CipherSuite::ML_KEM_768` (0xFDEA) — the deployed PQ suite (two-mls-pq
/// `suite.rs`). Named by value so the constant cannot drift from the suite the
/// exporter's length guard pins.
const ML_KEM_768: CipherSuite = CipherSuite::new(65002);

type PqClient = client::Client<
    WithIdentityProvider<
        BasicIdentityProvider,
        WithCryptoProvider<CryptoKitMlKemProvider, BaseConfig>,
    >,
>;

fn pq_client(name: &[u8]) -> PqClient {
    let provider = CryptoKitMlKemProvider;
    let cs = provider
        .cipher_suite_provider(ML_KEM_768)
        .expect("cryptokit supports ML_KEM_768");

    let (signer, public_key) = cs.signature_key_generate().expect("Ed25519 keygen");

    let signing_identity = SigningIdentity::new(
        BasicCredential::new(name.to_vec()).into_credential(),
        public_key,
    );

    ClientBuilder::new()
        .crypto_provider(provider)
        .identity_provider(BasicIdentityProvider::new())
        .signing_identity(signing_identity, signer, ML_KEM_768)
        .build()
}

#[derive(Serialize)]
struct FixtureMessage {
    epoch: u64,
    sender_leaf: u32,
    ciphertext: String,
    plaintext: String,
}

#[derive(Serialize)]
struct Fixture {
    cipher_suite: u16,
    exporter_leaf: u32,
    exporter_frontier: Vec<(u32, String)>,
    export: String,
    messages: Vec<FixtureMessage>,
}

/// GENERATOR, not a correctness test: overwrites
/// `../mls-rs/test_data/swift-migration-mlkem768.json`. `#[ignore]`d so a
/// plain `cargo test` never dirties `test_data`; run it explicitly with
/// `cargo test -p mls-rs-crypto-cryptokit --features post-quantum --test
/// swift_export_pq -- --ignored`.
#[test]
#[ignore]
fn generate_pq_migration_fixture() {
    let mut alice_group = pq_client(b"alice")
        .create_group_with_id(
            b"pq-migration-fixture".to_vec(),
            Default::default(),
            Default::default(),
            Some(MlsTime::now()),
        )
        .unwrap();

    let bob = pq_client(b"bob");

    let bob_key_package: MlsMessage = bob
        .generate_key_package_message(Default::default(), Default::default(), Some(MlsTime::now()))
        .unwrap();

    alice_group.propose_add(bob_key_package, vec![]).unwrap();
    let commit_output = alice_group.commit(vec![]).unwrap();
    alice_group.apply_pending_commit().unwrap();

    let mut bob_group = bob
        .join_group(
            None,
            &commit_output.welcome_messages()[0],
            Some(MlsTime::now()),
        )
        .unwrap()
        .0;

    // Message A: prior epoch. Alice never processes it.
    let message_a = bob_group
        .encrypt_application_message(b"prior-epoch hello", vec![])
        .unwrap();

    let epoch_a = alice_group.context().epoch;

    // Advance one epoch via an empty commit. Alice and Bob process only the
    // commit -- never messages A or B.
    let commit_output = alice_group.commit(vec![]).unwrap();
    alice_group.apply_pending_commit().unwrap();
    bob_group
        .process_incoming_message(commit_output.commit_message().clone())
        .unwrap();

    // Message B: current epoch. Alice never processes it.
    let message_b = bob_group
        .encrypt_application_message(b"current-epoch hello", vec![])
        .unwrap();

    let epoch_b = alice_group.context().epoch;
    assert_eq!(epoch_b, epoch_a + 1, "exactly one epoch advanced");

    let export = alice_group.export_for_swift().unwrap();

    // Self-check on a CLONE, so Alice's real (exported) state stays
    // unconsumed: prove her pre-migration state decrypts both messages fresh.
    let mut alice_check = alice_group.clone();

    match alice_check
        .process_incoming_message(message_a.clone())
        .unwrap()
    {
        ReceivedMessage::ApplicationMessage(m) => assert_eq!(
            m.data(),
            b"prior-epoch hello",
            "self-check: message A decrypted to unexpected plaintext"
        ),
        other => panic!("self-check: message A was not an application message: {other:?}"),
    }

    match alice_check
        .process_incoming_message(message_b.clone())
        .unwrap()
    {
        ReceivedMessage::ApplicationMessage(m) => assert_eq!(
            m.data(),
            b"current-epoch hello",
            "self-check: message B decrypted to unexpected plaintext"
        ),
        other => panic!("self-check: message B was not an application message: {other:?}"),
    }

    // The PQ half of the contract: every exported tree-secret key is the
    // 96-byte CryptoKit representation (the exporter's length guard would
    // have failed the export otherwise).
    assert_export_carries_cryptokit_ml_kem_secrets(&export);

    let fixture = Fixture {
        // Alice created the group, so she is leaf 0 and the exporting member.
        cipher_suite: 65002,
        exporter_leaf: 0,
        exporter_frontier: decode_exporter_frontier(&export),
        export: hex::encode(&export),
        messages: vec![
            FixtureMessage {
                epoch: epoch_a,
                sender_leaf: 1,
                ciphertext: hex::encode(message_a.to_bytes().unwrap()),
                plaintext: hex::encode(b"prior-epoch hello"),
            },
            FixtureMessage {
                epoch: epoch_b,
                sender_leaf: 1,
                ciphertext: hex::encode(message_b.to_bytes().unwrap()),
                plaintext: hex::encode(b"current-epoch hello"),
            },
        ],
    };

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../mls-rs/test_data/swift-migration-mlkem768.json"
    );

    std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();

    eprintln!("wrote fixture to {path}");
}

/// Decodes the exported format-2 CBOR and asserts every membership
/// `tree_secret_keys` value is exactly 96 bytes — the CryptoKit
/// `integrityCheckedRepresentation` ML-KEM-768 form swift-mls's provider
/// reconstructs (KAT-proven the byte form; the exporter's own
/// length guard is the enforcement, this is the proof it passed).
fn assert_export_carries_cryptokit_ml_kem_secrets(export: &[u8]) {
    let value: ciborium::Value = ciborium::from_reader(export).unwrap();
    let top = value.into_map().expect("top level is a map");

    let core = top
        .iter()
        .find(|(k, _)| k == &ciborium::Value::from(1u64))
        .expect("core key 1")
        .1
        .as_map()
        .expect("core is a map");

    let memberships = top
        .iter()
        .find(|(k, _)| k == &ciborium::Value::from(2u64))
        .expect("memberships key 2")
        .1
        .as_map()
        .expect("memberships is a map");

    for (leaf, membership) in memberships {
        let tree_secret_keys = membership
            .as_map()
            .expect("membership is a map")
            .iter()
            .find(|(k, _)| k == &ciborium::Value::from(0u64))
            .expect("tree_secret_keys key 0")
            .1
            .as_map()
            .expect("tree_secret_keys is a map");

        for (node, secret) in tree_secret_keys {
            let secret = secret.as_bytes().expect("secret key is bytes");
            assert_eq!(
                secret.len(),
                96,
                "membership {leaf:?} node {node:?}: ML-KEM-768 secret must be the 96-byte CryptoKit representation"
            );
        }

        assert!(
            !core.is_empty(),
            "core carries the PQ epoch secrets alongside the membership"
        );
    }
}

/// Pulls the exporter-tree frontier (core key 8 -> node_secrets key 1) back
/// out of the export for slice-C cross-checking.
fn decode_exporter_frontier(export: &[u8]) -> Vec<(u32, String)> {
    let value: ciborium::Value = ciborium::from_reader(export).unwrap();
    let top = value.into_map().expect("top level is a map");

    let core = top
        .iter()
        .find(|(k, _)| k == &ciborium::Value::from(1u64))
        .unwrap()
        .1
        .as_map()
        .expect("core is a map");

    let exporter_tree = core
        .iter()
        .find(|(k, _)| k == &ciborium::Value::from(8u64))
        .unwrap()
        .1
        .as_map()
        .expect("exporter_tree is a map");

    let node_secrets = exporter_tree
        .iter()
        .find(|(k, _)| k == &ciborium::Value::from(1u64))
        .unwrap()
        .1
        .as_map()
        .expect("node_secrets is a map");

    node_secrets
        .iter()
        .map(|(k, v)| {
            (
                u32::try_from(k.as_integer().expect("node index is an integer"))
                    .expect("node index fits u32"),
                hex::encode(v.as_bytes().expect("node secret is bytes")),
            )
        })
        .collect()
}
