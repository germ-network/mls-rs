// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

//! PROTOTYPE: reads a live `Group`'s in-memory state directly (no snapshot
//! decode) and emits the swift-mls archive format described by
//! `swift-mls/spec/snapshot.md` (§3 encoding, §4 schema). This is migration
//! code for moving an in-flight session into swift-mls, not a general
//! serialization path -- see `Group::export_for_swift` below for the scope
//! limits this prototype leaves as TODOs.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use ciborium::Value;
use mls_rs_codec::MlsEncode;
use zeroize::Zeroizing;

use crate::client::MlsError;
use crate::client_config::ClientConfig;
use crate::tree_kem::node::NodeIndex;

use super::epoch::EpochSecrets;
use super::secret_tree::ExportedSecretTreeEntry;
use super::Group;

/// Pure-data mapping of a `Group`'s live state onto the swift-mls snapshot
/// schema (§4.1). No crypto types: everything here is already the raw bytes
/// the archive wants, so this struct's construction (the mapping) and
/// `to_cbor` (the serialization) can be tested independently.
pub(crate) struct SwiftGroupArchive {
    pub(crate) group_context: Vec<u8>,
    pub(crate) ratchet_tree: Vec<u8>,
    pub(crate) interim_transcript_hash: Vec<u8>,
    pub(crate) my_leaf_index: u32,
    pub(crate) epoch_secrets: SwiftEpochSecrets,
    pub(crate) tree_secret_keys: BTreeMap<u32, Zeroizing<Vec<u8>>>,
    pub(crate) resumption_psks: BTreeMap<u64, Zeroizing<Vec<u8>>>,
    pub(crate) message_secrets: BTreeMap<u64, SwiftMessageSecretStore>,
    pub(crate) retention: SwiftRetention,
}

pub(crate) struct SwiftEpochSecrets {
    pub(crate) init_secret: Zeroizing<Vec<u8>>,
    pub(crate) exporter_secret: Zeroizing<Vec<u8>>,
    pub(crate) epoch_authenticator: Zeroizing<Vec<u8>>,
    pub(crate) membership_key: Zeroizing<Vec<u8>>,
}

pub(crate) struct SwiftMessageSecretStore {
    pub(crate) group_context: Vec<u8>,
    pub(crate) sender_data_secret: Zeroizing<Vec<u8>>,
    pub(crate) signature_keys: BTreeMap<u32, Vec<u8>>,
    pub(crate) secret_tree: SwiftSecretTreeState,
    pub(crate) chains: BTreeMap<u64, SwiftChain>,
    /// (handshake, application), per §4.3.
    pub(crate) own_next_generation: (u32, u32),
}

pub(crate) struct SwiftSecretTreeState {
    pub(crate) leaf_count: u32,
    pub(crate) node_secrets: BTreeMap<u32, Zeroizing<Vec<u8>>>,
}

pub(crate) struct SwiftChain {
    pub(crate) head_generation: u32,
    /// Always `Some` for this prototype -- see `ExportedChain::head_secret`.
    pub(crate) head_secret: Option<Zeroizing<Vec<u8>>>,
    pub(crate) skipped: BTreeMap<u32, (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>,
}

pub(crate) struct SwiftRetention {
    pub(crate) resumption_psk_depth: u32,
    pub(crate) message_secrets_depth: u32,
    pub(crate) max_forward_jump: u32,
    pub(crate) max_skipped_keys_per_sender: u32,
}

fn key(n: u64) -> Value {
    Value::from(n)
}

fn bytes_map<'a>(entries: impl Iterator<Item = (u64, &'a [u8])>) -> Value {
    Value::Map(
        entries
            .map(|(k, v)| (key(k), Value::from(v.to_vec())))
            .collect(),
    )
}

impl SwiftGroupArchive {
    /// Encodes this archive as one deterministic CBOR item per spec §3:
    /// definite lengths, integer map keys in strictly increasing order (our
    /// maps are all `BTreeMap`s, so iteration order already is that order),
    /// no floats, shortest-form heads (ciborium always encodes integers at
    /// their minimal width). Byte-exact conformance against the spec's
    /// golden vectors (§8) is deferred; this only guarantees the structural
    /// properties above.
    pub(crate) fn to_cbor(&self) -> Result<Vec<u8>, MlsError> {
        let mut out = Vec::new();

        ciborium::into_writer(&self.to_value(), &mut out)
            .map_err(|_| MlsError::SwiftExportEncodingFailed)?;

        Ok(out)
    }

    fn to_value(&self) -> Value {
        Value::Map(vec![
            (key(0), Value::from(1u64)), // format
            (key(1), Value::from(self.group_context.clone())),
            (key(2), Value::from(self.ratchet_tree.clone())),
            (key(3), Value::from(self.interim_transcript_hash.clone())),
            (key(4), Value::from(self.my_leaf_index as u64)),
            (key(5), self.epoch_secrets.to_value()),
            (
                key(6),
                bytes_map(
                    self.tree_secret_keys
                        .iter()
                        .map(|(k, v)| (*k as u64, v.as_slice())),
                ),
            ),
            (
                key(7),
                bytes_map(self.resumption_psks.iter().map(|(k, v)| (*k, v.as_slice()))),
            ),
            (
                key(8),
                Value::Map(
                    self.message_secrets
                        .iter()
                        .map(|(k, v)| (key(*k), v.to_value()))
                        .collect(),
                ),
            ),
            (key(9), self.retention.to_value()),
        ])
    }
}

impl SwiftEpochSecrets {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (key(0), Value::from(self.init_secret.to_vec())),
            (key(1), Value::from(self.exporter_secret.to_vec())),
            (key(2), Value::from(self.epoch_authenticator.to_vec())),
            (key(3), Value::from(self.membership_key.to_vec())),
        ])
    }
}

impl SwiftMessageSecretStore {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (key(0), Value::from(self.group_context.clone())),
            (key(1), Value::from(self.sender_data_secret.to_vec())),
            (
                key(2),
                bytes_map(
                    self.signature_keys
                        .iter()
                        .map(|(k, v)| (*k as u64, v.as_slice())),
                ),
            ),
            (key(3), self.secret_tree.to_value()),
            (
                key(4),
                Value::Map(
                    self.chains
                        .iter()
                        .map(|(k, v)| (key(*k), v.to_value()))
                        .collect(),
                ),
            ),
            (
                key(5),
                Value::Map(vec![
                    (key(0), Value::from(self.own_next_generation.0 as u64)),
                    (key(1), Value::from(self.own_next_generation.1 as u64)),
                ]),
            ),
        ])
    }
}

impl SwiftSecretTreeState {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (key(0), Value::from(self.leaf_count as u64)),
            (
                key(1),
                bytes_map(
                    self.node_secrets
                        .iter()
                        .map(|(k, v)| (*k as u64, v.as_slice())),
                ),
            ),
        ])
    }
}

impl SwiftChain {
    fn to_value(&self) -> Value {
        let mut fields = vec![(key(0), Value::from(self.head_generation as u64))];

        if let Some(secret) = &self.head_secret {
            fields.push((key(1), Value::from(secret.to_vec())));
        }

        fields.push((
            key(2),
            Value::Map(
                self.skipped
                    .iter()
                    .map(|(generation, (k, n))| {
                        (
                            key(*generation as u64),
                            Value::Map(vec![
                                (key(0), Value::from(k.to_vec())),
                                (key(1), Value::from(n.to_vec())),
                            ]),
                        )
                    })
                    .collect(),
            ),
        ));

        Value::Map(fields)
    }
}

impl SwiftRetention {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (key(0), Value::from(self.resumption_psk_depth as u64)),
            (key(1), Value::from(self.message_secrets_depth as u64)),
            (key(2), Value::from(self.max_forward_jump as u64)),
            (key(3), Value::from(self.max_skipped_keys_per_sender as u64)),
        ])
    }
}

impl<C> Group<C>
where
    C: ClientConfig,
{
    /// PROTOTYPE: exports this group's live state as a swift-mls snapshot
    /// archive (CBOR bytes). `message_secrets` and `resumption_psks` carry
    /// every retained prior epoch (`Group.state_repo`) in addition to the
    /// current one (GER-2372 scope decision B2), and `retention` reflects
    /// the actual count exported (B1). Remaining scope limits, each a TODO
    /// to resolve before this is anything but a prototype:
    ///
    /// - B3 (`pending_commit`): a pending commit awaiting confirmation has
    ///   no representation in this format, so it's a hard error rather than
    ///   a silent drop.
    /// - B4 (`pending_updates`): an outstanding by-reference self-Update's
    ///   new leaf secret is runtime-only handoff state (unarchivable), so a
    ///   mid-update export is a hard error rather than a silent drop that
    ///   would leave the restored session unable to adopt the update.
    ///
    /// `signer` is excluded by the target format's own design (snapshot.md
    /// §2) and is never considered here.
    ///
    /// `pub` (not `pub(crate)`): the dual-write caller is a separate crate
    /// (two-mls-pq), and it also roots the mapping/encoding chain so the
    /// feature build stays warning-clean.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn export_for_swift(&self) -> Result<Vec<u8>, MlsError> {
        if !self.pending_commit.is_none() {
            return Err(MlsError::SwiftExportPendingCommitUnsupported);
        }

        // B4: an outstanding self-Update's new leaf secret lives only in the
        // updater-side handoff (runtime state, unarchivable), so refuse a
        // mid-update export rather than drop a secret the restored session
        // needs to adopt the update. Symmetric with swift-mls's own
        // archive(), which throws on a non-nil pendingUpdate. Safe because
        // the dual-write fires every epoch: the next clean epoch exports.
        #[cfg(feature = "by_ref_proposal")]
        if !self.pending_updates.is_empty() {
            return Err(MlsError::SwiftExportPendingUpdatesUnsupported);
        }

        let group_context = self.context().mls_encode_to_vec()?;
        let epoch = self.context().epoch;
        let own_node_index: NodeIndex = self.private_tree.self_index.into();

        // key 6: raw HpkeSecretKey bytes verbatim. Format 1 is classical-only,
        // where these are canonical per-suite encodings and group_context's
        // cipher suite is enough to parse them -- so format 1 carries no
        // provider marker. PQ/hybrid keys are provider-specific (cryptokit vs
        // awslc differ); a provider marker for them is a Track-2 addition,
        // co-spec'd with the PQ key-6 encoding, not anchored here.
        let mut tree_secret_keys = BTreeMap::new();

        if let Some(own_secret) = self
            .private_tree
            .secret_keys
            .first()
            .and_then(|k| k.as_ref())
        {
            tree_secret_keys.insert(own_node_index, Zeroizing::new(own_secret.as_ref().to_vec()));
        }

        let copath = self
            .state
            .public_tree
            .nodes
            .direct_copath(self.private_tree.self_index);

        for (i, copath_node) in copath.iter().enumerate() {
            if let Some(secret) = self
                .private_tree
                .secret_keys
                .get(i + 1)
                .and_then(|k| k.as_ref())
            {
                tree_secret_keys.insert(copath_node.path, Zeroizing::new(secret.as_ref().to_vec()));
            }
        }

        let mut signature_keys = BTreeMap::new();

        for (leaf_index, leaf) in self.state.public_tree.nodes.non_empty_leaves() {
            signature_keys.insert(
                *leaf_index,
                leaf.signing_identity.signature_key.as_ref().to_vec(),
            );
        }

        let mut message_secrets = BTreeMap::new();

        message_secrets.insert(
            epoch,
            message_store_from(
                group_context.clone(),
                own_node_index,
                &self.epoch_secrets,
                signature_keys,
            ),
        );

        let mut resumption_psks = BTreeMap::new();

        #[cfg(feature = "psk")]
        resumption_psks.insert(
            epoch,
            Zeroizing::new(self.epoch_secrets.resumption_secret.as_ref().to_vec()),
        );

        // B2: walk every retained prior epoch from `current_epoch - 1`
        // downward, stopping at the first miss -- there's no fixed
        // retention depth to assume, so this can't just loop a constant
        // number of times.
        let mut prior_epoch_id = epoch;

        while prior_epoch_id > 0 {
            prior_epoch_id -= 1;

            let Some(prior) = self.state_repo.get_epoch(prior_epoch_id).await? else {
                break;
            };

            let prior_context = prior.context.mls_encode_to_vec()?;
            let prior_own_node_index: NodeIndex = prior.self_index.into();

            let prior_signature_keys = prior
                .signature_public_keys
                .iter()
                .enumerate()
                .filter_map(|(leaf_index, key)| {
                    key.as_ref()
                        .map(|key| (leaf_index as u32, key.as_ref().to_vec()))
                })
                .collect();

            message_secrets.insert(
                prior_epoch_id,
                message_store_from(
                    prior_context,
                    prior_own_node_index,
                    &prior.secrets,
                    prior_signature_keys,
                ),
            );

            #[cfg(feature = "psk")]
            resumption_psks.insert(
                prior_epoch_id,
                Zeroizing::new(prior.secrets.resumption_secret.as_ref().to_vec()),
            );
        }

        let archive = SwiftGroupArchive {
            group_context,
            ratchet_tree: self.export_tree().to_bytes()?,
            interim_transcript_hash: self.state.interim_transcript_hash.to_vec(),
            my_leaf_index: *self.private_tree.self_index,
            epoch_secrets: SwiftEpochSecrets {
                init_secret: self.key_schedule.raw_init_secret().clone(),
                exporter_secret: self.key_schedule.raw_exporter_secret().clone(),
                epoch_authenticator: self.key_schedule.authentication_secret.clone(),
                membership_key: self.key_schedule.membership_key.clone(),
            },
            tree_secret_keys,
            retention: SwiftRetention {
                resumption_psk_depth: resumption_psks.len() as u32,
                message_secrets_depth: message_secrets.len() as u32,
                max_forward_jump: super::secret_tree::MAX_RATCHET_BACK_HISTORY,
                max_skipped_keys_per_sender: super::secret_tree::MAX_RATCHET_BACK_HISTORY,
            },
            resumption_psks,
            message_secrets,
        };

        archive.to_cbor()
    }
}

/// Shared mapping path (§4.3) for both the current epoch (`Group.epoch_secrets`)
/// and every retained prior epoch (`PriorEpoch.secrets`, same `EpochSecrets`
/// type) -- so the two never drift apart. `own_node_index` is the exporting
/// group member's own leaf, converted from that epoch's own `self_index`
/// (current or historical), used only to pick out `own_next_generation`.
fn message_store_from(
    group_context: Vec<u8>,
    own_node_index: NodeIndex,
    epoch_secrets: &EpochSecrets,
    signature_keys: BTreeMap<u32, Vec<u8>>,
) -> SwiftMessageSecretStore {
    let leaf_count = epoch_secrets.secret_tree.leaf_count();
    let mut node_secrets = BTreeMap::new();
    let mut chains = BTreeMap::new();
    let mut own_next_generation = (0u32, 0u32);

    for (node_index, entry) in epoch_secrets.secret_tree.export_entries() {
        match entry {
            ExportedSecretTreeEntry::Secret(secret) => {
                node_secrets.insert(node_index, secret);
            }
            ExportedSecretTreeEntry::Ratchet {
                application,
                handshake,
            } => {
                if node_index == own_node_index {
                    own_next_generation = (handshake.head_generation, application.head_generation);
                }

                let leaf = node_index as u64 / 2;
                chains.insert(leaf << 1, exported_chain_to_swift(handshake));
                chains.insert((leaf << 1) | 1, exported_chain_to_swift(application));
            }
        }
    }

    SwiftMessageSecretStore {
        group_context,
        sender_data_secret: Zeroizing::new(epoch_secrets.sender_data_secret.as_ref().to_vec()),
        signature_keys,
        secret_tree: SwiftSecretTreeState {
            leaf_count,
            node_secrets,
        },
        chains,
        own_next_generation,
    }
}

fn exported_chain_to_swift(chain: super::secret_tree::ExportedChain) -> SwiftChain {
    SwiftChain {
        head_generation: chain.head_generation,
        head_secret: Some(chain.head_secret),
        skipped: chain
            .skipped
            .into_iter()
            .map(|(generation, k, n)| (generation, (k, n)))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use ciborium::Value;

    use crate::{
        cipher_suite::CipherSuite,
        client::test_utils::{TEST_CIPHER_SUITE, TEST_PROTOCOL_VERSION},
        group::test_utils::test_n_member_group,
    };

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn export_for_swift_has_expected_shape() {
        let cipher_suite: CipherSuite = TEST_CIPHER_SUITE;
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, cipher_suite, 2).await;

        // Advance an epoch with an empty commit so the pre-commit epoch
        // becomes a retained prior epoch (B2) alongside the new current
        // epoch. (Adding bob already advanced the group once, by way of
        // `test_n_member_group`'s own commit, so this is the second prior
        // epoch alice will have on record.)
        let commit_output = groups[0].commit(vec![]).await.unwrap();
        groups[0].apply_pending_commit().await.unwrap();

        groups[1]
            .process_incoming_message(commit_output.commit_message)
            .await
            .unwrap();

        let msg = groups[1]
            .encrypt_application_message(b"hello", vec![])
            .await
            .unwrap();

        groups[0].process_incoming_message(msg).await.unwrap();

        let current_epoch = groups[0].context().epoch;

        let bytes = groups[0].export_for_swift().await.unwrap();

        let value: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let top = value.into_map().expect("top level is a map");

        let get = |k: u64| -> &Value {
            top.iter()
                .find(|(key, _)| key == &Value::from(k))
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("missing top-level key {k}"))
        };

        assert_eq!(get(0), &Value::from(1u64));
        assert!(!get(2).as_bytes().unwrap().is_empty(), "ratchet_tree");

        let tree_secret_keys = get(6).as_map().expect("tree_secret_keys is a map");
        assert!(
            !tree_secret_keys.is_empty(),
            "tree_secret_keys must contain at least the own leaf"
        );

        let message_secrets = get(8).as_map().expect("message_secrets is a map");
        assert!(
            message_secrets.len() > 1,
            "expected the current epoch plus at least one retained prior epoch, got {}",
            message_secrets.len()
        );

        let resumption_psks = get(7).as_map().expect("resumption_psks is a map");
        assert_eq!(
            resumption_psks.len(),
            message_secrets.len(),
            "every exported epoch should also have a resumption secret"
        );

        for (epoch_key, store) in message_secrets.iter() {
            let store = store
                .as_map()
                .unwrap_or_else(|| panic!("message secret store for {epoch_key:?} is a map"));

            let group_context = store
                .iter()
                .find(|(k, _)| k == &Value::from(0u64))
                .unwrap()
                .1
                .as_bytes()
                .expect("group_context is bytes");

            assert!(
                !group_context.is_empty(),
                "group_context for {epoch_key:?} must be populated"
            );

            let secret_tree = store
                .iter()
                .find(|(k, _)| k == &Value::from(3u64))
                .unwrap()
                .1
                .as_map()
                .expect("secret_tree is a map");

            let node_secrets = secret_tree
                .iter()
                .find(|(k, _)| k == &Value::from(1u64))
                .unwrap()
                .1
                .as_map()
                .expect("node_secrets is a map");

            // Alice and Bob is a 2-leaf tree: consuming Bob's leaf ratchet
            // also splits the root into the two leaves' Secret entries, so
            // Alice's own leaf's interior frontier secret should still be
            // present for every epoch's tree.
            assert!(
                !node_secrets.is_empty(),
                "splitting the tree to reach bob's leaf should leave a node_secrets frontier for {epoch_key:?}"
            );
        }

        let current_epoch_store = message_secrets
            .iter()
            .find(|(k, _)| k == &Value::from(current_epoch))
            .expect("current epoch must be present")
            .1
            .as_map()
            .unwrap();

        let chains = current_epoch_store
            .iter()
            .find(|(k, _)| k == &Value::from(4u64))
            .unwrap()
            .1
            .as_map()
            .expect("chains is a map");

        assert!(
            !chains.is_empty(),
            "bob's application message must have advanced a chain in the current epoch"
        );

        assert!(
            message_secrets
                .iter()
                .any(|(k, _)| k != &Value::from(current_epoch)),
            "at least one retained prior epoch must be present"
        );

        let retention = get(9).as_map().expect("retention is a map");

        let message_secrets_depth = retention
            .iter()
            .find(|(k, _)| k == &Value::from(1u64))
            .unwrap()
            .1
            .as_integer()
            .unwrap();

        assert_eq!(
            message_secrets_depth,
            ciborium::value::Integer::from(message_secrets.len() as u64),
            "retention.message_secrets_depth must match the number of epochs exported"
        );

        let resumption_psk_depth = retention
            .iter()
            .find(|(k, _)| k == &Value::from(0u64))
            .unwrap()
            .1
            .as_integer()
            .unwrap();

        assert_eq!(
            resumption_psk_depth,
            ciborium::value::Integer::from(resumption_psks.len() as u64),
            "retention.resumption_psk_depth must match the number of epochs exported"
        );
    }
}
