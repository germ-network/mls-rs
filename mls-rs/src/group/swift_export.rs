// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

//! PROTOTYPE: reads a live `Group`'s in-memory state directly (no snapshot
//! decode) and emits the swift-mls **format 2** snapshot archive described by
//! `swift-mls/spec/snapshot.md` (§3 encoding, §4.1-§4.6 schema; format 1, §4.7,
//! is decode-only and no longer emitted). This is migration code for moving an
//! in-flight session into swift-mls, not a general serialization path -- see
//! `Group::export_for_swift` below for the scope limits.
//!
//! Format 2 (spec/snapshot.md §4.1) is a client-agnostic `core` plus one
//! `Membership` per local membership, keyed by leaf index. mls-rs `Group`s have
//! exactly one local membership (the exporting client), so `memberships` always
//! carries that single entry.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use ciborium::Value;
use core::ops::RangeInclusive;
use mls_rs_codec::MlsEncode;
use zeroize::Zeroizing;

use crate::crypto::{HpkePublicKey, HpkeSecretKey, SignatureSecretKey};

use crate::client::MlsError;
use crate::client_config::ClientConfig;
use crate::map::SmallMap;
use crate::tree_kem::node::NodeIndex;

use super::epoch::EpochSecrets;
use super::secret_tree::ExportedSecretTreeEntry;
use super::Group;

/// Pure-data mapping of a `Group`'s live state onto the swift-mls snapshot
/// schema (spec/snapshot.md §4.1). No crypto types: everything here is already
/// the raw bytes the archive wants, so this struct's construction (the mapping)
/// and `to_cbor` (the serialization) can be tested independently.
pub(crate) struct SwiftSnapshot {
    pub(crate) core: SwiftCoreArchive,
    pub(crate) memberships: BTreeMap<u32, SwiftMembershipArchive>,
}

pub(crate) struct SwiftCoreArchive {
    pub(crate) group_context: Vec<u8>,
    pub(crate) ratchet_tree: Vec<u8>,
    pub(crate) interim_transcript_hash: Vec<u8>,
    pub(crate) epoch_secrets: SwiftEpochSecrets,
    pub(crate) resumption_psks: BTreeMap<u64, Zeroizing<Vec<u8>>>,
    pub(crate) message_secrets: BTreeMap<u64, SwiftMessageSecretStore>,
    pub(crate) retention: SwiftRetention,
    /// The current epoch's exporter-tree frontier (spec/snapshot.md §4.6). A
    /// conforming format-2 producer always emits it.
    pub(crate) exporter_tree: SwiftSecretTreeState,
}

/// One local membership's per-client state (spec/snapshot.md §4.1.2), keyed in
/// `SwiftSnapshot::memberships` by leaf index.
pub(crate) struct SwiftMembershipArchive {
    pub(crate) tree_secret_keys: BTreeMap<u32, Zeroizing<Vec<u8>>>,
    /// Absent when the group has no outstanding self-Update (spec §4.1.2:
    /// "Absent when none is outstanding, never empty when present").
    pub(crate) pending_updates: Option<BTreeMap<u64, SwiftPendingUpdateEntry>>,
    /// This membership's own send ratchets for the current epoch, lifted out
    /// of the current epoch's `chains` (spec/snapshot.md §4.3: a store's
    /// `chains` holds remote senders only). Absent when the membership has not
    /// sent this epoch.
    pub(crate) own_send: Option<SwiftOwnSend>,
}

/// One proposed new leaf key pair in a pending self-Update (spec/snapshot.md
/// §4.1.2). The signer a pending update may also carry has no representation in
/// the format (§2 excludes signature private keys) and is refused at export.
pub(crate) struct SwiftPendingUpdateEntry {
    pub(crate) public_key: Vec<u8>,
    pub(crate) secret: Zeroizing<Vec<u8>>,
}

pub(crate) struct SwiftOwnSend {
    pub(crate) handshake_chain: SwiftChain,
    pub(crate) application_chain: SwiftChain,
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
    /// Remote senders' ratchets only (spec/snapshot.md §4.3), keyed
    /// `(leaf << 1) | kind`.
    pub(crate) chains: BTreeMap<u64, SwiftChain>,
}

pub(crate) struct SwiftSecretTreeState {
    pub(crate) leaf_count: u32,
    pub(crate) node_secrets: BTreeMap<u32, Zeroizing<Vec<u8>>>,
}

pub(crate) struct SwiftChain {
    pub(crate) head_generation: u32,
    /// Always `Some` for this exporter -- see `ExportedChain::head_secret`.
    pub(crate) head_secret: Option<Zeroizing<Vec<u8>>>,
    pub(crate) skipped: SwiftSkippedKeys,
}

type SwiftSkippedKeys = BTreeMap<u32, (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>;

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

/// `CipherSuite` values this exporter may emit: the classical RFC 9420 suites
/// swift-mls implements, plus the deployed PQ suite. Anything else would
/// produce an archive no swift-mls consumer can restore, so it is refused.
const SWIFT_CLASSICAL_SUITES: RangeInclusive<u16> = 1..=7;
/// `CipherSuite::ML_KEM_768` (0xFDEA). Referenced by value, not by the
/// `post-quantum`-gated constant, so the export path does not depend on that
/// feature.
const ML_KEM_768_SUITE: u16 = 65002;
/// CryptoKit stores ML-KEM-768 private keys as the 96-byte
/// `integrityCheckedRepresentation` (`mls-rs-crypto-cryptokit/src/ml_kem.rs`),
/// the form swift-mls's Apple provider reconstructs. AWS-LC's 2400-byte FIPS
/// 203 expanded key is NOT interchangeable and is refused at export rather
/// than shipped to fail at first decapsulation.
const ML_KEM_768_CRYPTOKIT_SECRET_LEN: usize = 96;

/// Suite-dependent length check for one exported KEM secret key
/// (spec/snapshot.md §3.1: every length-constrained byte string MUST be
/// exactly `Nsk`). Classical suites carry canonical scalar encodings; the PQ
/// suite's secret is provider-specific, so its form is pinned here.
fn check_secret_key_len(suite: u16, key: &[u8]) -> Result<(), MlsError> {
    let expected = match suite {
        1..=3 => 32, // X25519, P-256, X25519 (0x0003 DHKEMX25519_CHACHA20POLY1305)
        7 => 48,     // P-384
        4 | 6 => 56, // X448
        5 => 66,     // P-521
        ML_KEM_768_SUITE => ML_KEM_768_CRYPTOKIT_SECRET_LEN,
        // The suite allowlist is checked before any secret is touched.
        _ => return Ok(()),
    };

    if key.len() != expected {
        return Err(MlsError::SwiftExportSecretKeyLengthMismatch {
            expected,
            actual: key.len(),
        });
    }

    Ok(())
}

impl SwiftSnapshot {
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
            (key(0), Value::from(2u64)), // format
            (key(1), self.core.to_value()),
            (
                key(2),
                Value::Map(
                    self.memberships
                        .iter()
                        .map(|(leaf, membership)| (key(*leaf as u64), membership.to_value()))
                        .collect(),
                ),
            ),
        ])
    }
}

impl SwiftCoreArchive {
    /// spec/snapshot.md §4.1.1. Key 7 (`config`) is never emitted: §4.5
    /// defines no config keys and swift-mls rejects a present section.
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (key(0), Value::from(self.group_context.clone())),
            (key(1), Value::from(self.ratchet_tree.clone())),
            (key(2), Value::from(self.interim_transcript_hash.clone())),
            (key(3), self.epoch_secrets.to_value()),
            (
                key(4),
                bytes_map(self.resumption_psks.iter().map(|(k, v)| (*k, v.as_slice()))),
            ),
            (
                key(5),
                Value::Map(
                    self.message_secrets
                        .iter()
                        .map(|(k, v)| (key(*k), v.to_value()))
                        .collect(),
                ),
            ),
            (key(6), self.retention.to_value()),
            (key(8), self.exporter_tree.to_value()),
        ])
    }
}

impl SwiftMembershipArchive {
    /// spec/snapshot.md §4.1.2: keys 1 and 2 are optional and absent entirely
    /// when they do not apply (§3: absence is their only encoding).
    fn to_value(&self) -> Value {
        let mut fields = vec![(
            key(0),
            bytes_map(
                self.tree_secret_keys
                    .iter()
                    .map(|(k, v)| (*k as u64, v.as_slice())),
            ),
        )];

        if let Some(pending) = &self.pending_updates {
            fields.push((
                key(1),
                Value::Map(
                    pending
                        .iter()
                        .map(|(k, entry)| (key(*k), entry.to_value()))
                        .collect(),
                ),
            ));
        }

        if let Some(own_send) = &self.own_send {
            fields.push((key(2), own_send.to_value()));
        }

        Value::Map(fields)
    }
}

impl SwiftPendingUpdateEntry {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (key(0), Value::from(self.public_key.clone())),
            (key(1), Value::from(self.secret.to_vec())),
        ])
    }
}

impl SwiftOwnSend {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (key(0), self.handshake_chain.to_value()),
            (key(1), self.application_chain.to_value()),
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
    /// PROTOTYPE: exports this group's live state as a swift-mls **format 2**
    /// snapshot archive (CBOR bytes). `message_secrets` and `resumption_psks`
    /// carry every retained prior epoch (`Group.state_repo`) in addition to the
    /// current one, and `retention` reflects the actual count exported. The
    /// exporting member's per-client state (tree secret keys, own send
    /// ratchets, outstanding self-Update) is the single `memberships` entry.
    ///
    /// Remaining scope limit: a pending commit awaiting confirmation has no
    /// representation in this format, so it's a hard error rather than a
    /// silent drop (`SwiftExportPendingCommitUnsupported`). A pending
    /// self-Update IS carried (`memberships[].pending_updates`), but one that
    /// also rotates the signing identity is refused
    /// (`SwiftExportPendingUpdateSignerUnsupported`): the format has no field
    /// for the replacement signer.
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

        let group_context = self.context().mls_encode_to_vec()?;
        let suite: u16 = u16::from(self.context().cipher_suite);

        if !SWIFT_CLASSICAL_SUITES.contains(&suite) && suite != ML_KEM_768_SUITE {
            return Err(MlsError::SwiftExportCipherSuiteUnsupported);
        }

        let epoch = self.context().epoch;
        let own_leaf_index = *self.private_tree.self_index;
        let own_node_index: NodeIndex = self.private_tree.self_index.into();

        // Membership key 0 (spec/snapshot.md §4.1.2): raw HpkeSecretKey bytes
        // along the member's own direct path, own leaf first.
        let mut tree_secret_keys = BTreeMap::new();

        if let Some(own_secret) = self
            .private_tree
            .secret_keys
            .first()
            .and_then(|k| k.as_ref())
        {
            check_secret_key_len(suite, own_secret.as_ref())?;
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
                check_secret_key_len(suite, secret.as_ref())?;
                tree_secret_keys.insert(copath_node.path, Zeroizing::new(secret.as_ref().to_vec()));
            }
        }

        // spec/snapshot.md §4.1.2 key 0: "Never empty: a member always holds at
        // least its own leaf key." Emitting an empty map would be bytes swift-mls
        // rejects at restore, so refuse here instead.
        if tree_secret_keys.is_empty() {
            return Err(MlsError::SwiftExportMembershipStateInvalid);
        }

        let pending_updates = pending_updates_from(&self.pending_updates, suite)?;

        let mut signature_keys = BTreeMap::new();

        for (leaf_index, leaf) in self.state.public_tree.nodes.non_empty_leaves() {
            signature_keys.insert(
                *leaf_index,
                leaf.signing_identity.signature_key.as_ref().to_vec(),
            );
        }

        // Current epoch's store: the own-leaf chains are lifted out into the
        // membership's own_send (spec/snapshot.md §4.3: a store's chains hold
        // remote senders only).
        let (current_store, own_send) = message_store_from(
            group_context.clone(),
            own_node_index,
            &self.epoch_secrets,
            signature_keys,
            true,
        );

        let mut message_secrets = BTreeMap::new();
        message_secrets.insert(epoch, current_store);

        let mut resumption_psks = BTreeMap::new();

        resumption_psks.insert(
            epoch,
            Zeroizing::new(self.epoch_secrets.resumption_secret.as_ref().to_vec()),
        );

        // Walk every retained prior epoch from `current_epoch - 1` downward,
        // stopping at the first miss -- there's no fixed retention depth to
        // assume, so this can't just loop a constant number of times.
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

            // Retained epochs cannot be sent in, so their own-leaf chains are
            // dropped outright (spec/snapshot.md §4.7 restore does the same for
            // the format-1 decode path); `own_send` is current-epoch-only.
            let (prior_store, _) = message_store_from(
                prior_context,
                prior_own_node_index,
                &prior.secrets,
                prior_signature_keys,
                false,
            );

            message_secrets.insert(prior_epoch_id, prior_store);

            resumption_psks.insert(
                prior_epoch_id,
                Zeroizing::new(prior.secrets.resumption_secret.as_ref().to_vec()),
            );
        }

        let message_secrets_len = message_secrets.len();
        let resumption_psks_len = resumption_psks.len();

        let mut memberships = BTreeMap::new();
        memberships.insert(
            own_leaf_index,
            SwiftMembershipArchive {
                tree_secret_keys,
                pending_updates,
                own_send,
            },
        );

        let archive = SwiftSnapshot {
            core: SwiftCoreArchive {
                group_context,
                ratchet_tree: self.export_tree().to_bytes()?,
                interim_transcript_hash: self.state.interim_transcript_hash.to_vec(),
                epoch_secrets: SwiftEpochSecrets {
                    init_secret: self.key_schedule.raw_init_secret().clone(),
                    exporter_secret: self.key_schedule.raw_exporter_secret().clone(),
                    epoch_authenticator: self.key_schedule.authentication_secret.clone(),
                    membership_key: self.key_schedule.membership_key.clone(),
                },
                resumption_psks,
                message_secrets,
                retention: SwiftRetention {
                    resumption_psk_depth: resumption_psks_len as u32,
                    message_secrets_depth: message_secrets_len as u32,
                    max_forward_jump: super::secret_tree::MAX_RATCHET_BACK_HISTORY,
                    // Skipped keys only exist under `out_of_order`; without it
                    // the exporter could never have any, and telling the
                    // restored group it may hold them would misstate the
                    // policy it was persisted under.
                    max_skipped_keys_per_sender: if cfg!(feature = "out_of_order") {
                        super::secret_tree::MAX_RATCHET_BACK_HISTORY
                    } else {
                        0
                    },
                },
                // spec/snapshot.md §4.6: the current epoch's exporter tree, as
                // its surviving frontier. Every live group installs one.
                exporter_tree: exporter_tree_from(&self.epoch_secrets.exporter_tree)?,
            },
            memberships,
        };

        archive.to_cbor()
    }
}

/// Maps a pending-update set onto the membership's `pending_updates`
/// (spec/snapshot.md §4.1.2): dense index `0..<count`. The spec says "in
/// proposal order", but `SmallMap` is a `HashMap` under `std` and insertion
/// order is unrecoverable, so the entries are sorted by public-key bytes --
/// a deterministic order in place of proposal order. That is wire-compatible:
/// swift's restore only checks denseness, and the update set is a set (the
/// committer, not the proposer, picks which lands -- §4.1.2).
type PendingUpdateMap = SmallMap<HpkePublicKey, (HpkeSecretKey, Option<SignatureSecretKey>)>;

fn pending_updates_from(
    pending: &PendingUpdateMap,
    suite: u16,
) -> Result<Option<BTreeMap<u64, SwiftPendingUpdateEntry>>, MlsError> {
    if pending.is_empty() {
        return Ok(None);
    }

    let mut entries: Vec<(&HpkePublicKey, &(HpkeSecretKey, Option<SignatureSecretKey>))> =
        pending.iter().collect();

    entries.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));

    let mut mapped = BTreeMap::new();

    for (index, (public_key, (secret, signer))) in entries.into_iter().enumerate() {
        if signer.is_some() {
            return Err(MlsError::SwiftExportPendingUpdateSignerUnsupported);
        }

        check_secret_key_len(suite, secret.as_ref())?;

        mapped.insert(
            index as u64,
            SwiftPendingUpdateEntry {
                public_key: public_key.as_ref().to_vec(),
                secret: Zeroizing::new(secret.as_ref().to_vec()),
            },
        );
    }

    Ok(Some(mapped))
}

/// Shared mapping path (spec/snapshot.md §4.3) for both the current epoch
/// (`Group.epoch_secrets`) and every retained prior epoch (`PriorEpoch.secrets`,
/// same `EpochSecrets` type) -- so the two never drift apart. `own_node_index`
/// is the exporting group member's own leaf in that epoch, converted from that
/// epoch's own `self_index`.
///
/// When `lift_own_send` is set (the current epoch), the own leaf's two chains
/// are removed from the store's `chains` and returned as the membership's
/// `own_send`; otherwise (retained epochs, which cannot be sent in) they are
/// dropped. Either way the own-leaf chains never stay in the store.
fn message_store_from(
    group_context: Vec<u8>,
    own_node_index: NodeIndex,
    epoch_secrets: &EpochSecrets,
    signature_keys: BTreeMap<u32, Vec<u8>>,
    lift_own_send: bool,
) -> (SwiftMessageSecretStore, Option<SwiftOwnSend>) {
    let leaf_count = epoch_secrets.secret_tree.leaf_count();
    let mut node_secrets = BTreeMap::new();
    let mut chains = BTreeMap::new();
    let mut own_send = None;

    for (node_index, entry) in epoch_secrets.secret_tree.export_entries() {
        match entry {
            ExportedSecretTreeEntry::Secret(secret) => {
                node_secrets.insert(node_index, secret);
            }
            ExportedSecretTreeEntry::Ratchet {
                application,
                handshake,
            } => {
                let handshake_chain = exported_chain_to_swift(handshake);
                let application_chain = exported_chain_to_swift(application);

                if node_index == own_node_index {
                    // Own send ratchets live on the membership (§4.1.2), not in
                    // the store (§4.3). The leaf's Secret is consumed once a
                    // ratchet exists, so the restored group resumes from
                    // `own_send` and never needs this leaf secret.
                    if lift_own_send {
                        own_send = Some(SwiftOwnSend {
                            handshake_chain,
                            application_chain,
                        });
                    }
                } else {
                    let leaf = node_index as u64 / 2;
                    chains.insert(leaf << 1, handshake_chain);
                    chains.insert((leaf << 1) | 1, application_chain);
                }
            }
        }
    }

    (
        SwiftMessageSecretStore {
            group_context,
            sender_data_secret: Zeroizing::new(epoch_secrets.sender_data_secret.as_ref().to_vec()),
            signature_keys,
            secret_tree: SwiftSecretTreeState {
                leaf_count,
                node_secrets,
            },
            chains,
        },
        own_send,
    )
}

/// The current epoch's exporter tree as its surviving frontier
/// (spec/snapshot.md §4.6): a `SecretTreeState` with leaf_count exactly 2^16
/// and only node-`Secret` entries (the exporter tree never ratchets; a
/// `Ratchet` entry would mean the tree was used as a message secret tree,
/// which is not a state this exporter can represent).
fn exporter_tree_from(
    exporter_tree: &super::exporter_tree::ExporterTree,
) -> Result<SwiftSecretTreeState, MlsError> {
    use super::exporter_tree::ExporterTree;

    if exporter_tree.leaf_count() != ExporterTree::LEAF_COUNT {
        return Err(MlsError::SwiftExportExporterTreeInvalid);
    }

    let mut node_secrets = BTreeMap::new();

    for (node_index, entry) in exporter_tree.export_frontier() {
        match entry {
            ExportedSecretTreeEntry::Secret(secret) => {
                node_secrets.insert(node_index, secret);
            }
            ExportedSecretTreeEntry::Ratchet { .. } => {
                return Err(MlsError::SwiftExportExporterTreeInvalid);
            }
        }
    }

    Ok(SwiftSecretTreeState {
        leaf_count: ExporterTree::LEAF_COUNT,
        node_secrets,
    })
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
        // becomes a retained prior epoch alongside the new current epoch.
        // (Adding bob already advanced the group once, by way of
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

        fn get(map: &[(Value, Value)], k: u64) -> &Value {
            map.iter()
                .find(|(key, _)| key == &Value::from(k))
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("missing key {k}"))
        }

        assert_eq!(get(&top, 0), &Value::from(2u64), "format 2");

        let core = get(&top, 1).as_map().expect("core is a map");
        let memberships = get(&top, 2).as_map().expect("memberships is a map");
        assert_eq!(memberships.len(), 1, "one local membership");
        let own_leaf = *groups[0].private_tree.self_index;
        assert_eq!(
            memberships[0].0,
            Value::from(own_leaf as u64),
            "the membership is keyed by the exporting member's leaf index"
        );
        let membership = memberships[0].1.as_map().unwrap();

        assert!(!get(core, 2).as_bytes().unwrap().is_empty(), "ratchet_tree");

        // Membership key 0: tree_secret_keys on the own direct path, at least
        // the own leaf's.
        let tree_secret_keys = get(membership, 0).as_map().expect("tree_secret_keys");
        assert!(
            !tree_secret_keys.is_empty(),
            "tree_secret_keys must contain at least the own leaf"
        );
        assert!(
            tree_secret_keys
                .iter()
                .any(|(k, _)| k == &Value::from((own_leaf as u64) * 2)),
            "tree_secret_keys contains the own leaf's node (2 * leaf index)"
        );

        // Core key 8: the exporter-tree frontier, a 2^16-leaf tree with only
        // Nh-length node secrets.
        let exporter_tree = get(core, 8).as_map().expect("exporter_tree present");
        assert_eq!(
            get(exporter_tree, 0),
            &Value::from(1u64 << 16),
            "exporter tree leaf_count is exactly 2^16"
        );
        let exporter_secrets = get(exporter_tree, 1).as_map().expect("node_secrets");
        assert!(
            !exporter_secrets.is_empty(),
            "unexported tree keeps its root"
        );

        let message_secrets = get(core, 5).as_map().expect("message_secrets is a map");
        assert!(
            message_secrets.len() > 1,
            "expected the current epoch plus at least one retained prior epoch, got {}",
            message_secrets.len()
        );

        let resumption_psks = get(core, 4).as_map().expect("resumption_psks is a map");
        assert_eq!(
            resumption_psks.len(),
            message_secrets.len(),
            "every exported epoch should also have a resumption secret"
        );

        for (epoch_key, store) in message_secrets.iter() {
            let store = store
                .as_map()
                .unwrap_or_else(|| panic!("message secret store for {epoch_key:?} is a map"));

            let group_context = get(store, 0).as_bytes().expect("group_context is bytes");
            assert!(
                !group_context.is_empty(),
                "group_context for {epoch_key:?} must be populated"
            );

            // §4.3: format-2 stores have no key 5 (own_next_generation was
            // format-1 only).
            assert!(
                !store.iter().any(|(k, _)| k == &Value::from(5u64)),
                "format-2 store must not carry own_next_generation"
            );

            let secret_tree = get(store, 3).as_map().expect("secret_tree is a map");
            let node_secrets = get(secret_tree, 1).as_map().expect("node_secrets is a map");

            // Alice and Bob is a 2-leaf tree: consuming Bob's leaf ratchet
            // also splits the root into the two leaves' Secret entries, so
            // Alice's own leaf's interior frontier secret should still be
            // present for every epoch's tree.
            assert!(
                !node_secrets.is_empty(),
                "splitting the tree to reach bob's leaf should leave a node_secrets frontier for {epoch_key:?}"
            );

            // §4.3: chains hold remote senders only -- the own leaf's chains
            // are lifted into the membership's own_send (current epoch) or
            // dropped (retained epochs). No store chain may be keyed with the
            // exporting member's own leaf.
            let chains = get(store, 4).as_map().expect("chains is a map");
            let own_handshake_key = Value::from((own_leaf as u64) << 1);
            let own_application_key = Value::from(((own_leaf as u64) << 1) | 1);
            assert!(
                !chains
                    .iter()
                    .any(|(k, _)| k == &own_handshake_key || k == &own_application_key),
                "own-leaf chains must be stripped from the store for {epoch_key:?}"
            );
        }

        // The current epoch's own send state: alice never sent, so own_send is
        // absent and bob's application chain advanced instead.
        assert!(
            !membership.iter().any(|(k, _)| k == &Value::from(2u64)),
            "own_send absent when the membership has not sent this epoch"
        );

        let current_epoch_store = message_secrets
            .iter()
            .find(|(k, _)| k == &Value::from(current_epoch))
            .expect("current epoch must be present")
            .1
            .as_map()
            .unwrap();

        let chains = get(current_epoch_store, 4)
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

        let retention = get(core, 6).as_map().expect("retention is a map");

        let message_secrets_depth = get(retention, 1).as_integer().unwrap();

        assert_eq!(
            message_secrets_depth,
            ciborium::value::Integer::from(message_secrets.len() as u64),
            "retention.message_secrets_depth must match the number of epochs exported"
        );

        let resumption_psk_depth = get(retention, 0).as_integer().unwrap();

        assert_eq!(
            resumption_psk_depth,
            ciborium::value::Integer::from(resumption_psks.len() as u64),
            "retention.resumption_psk_depth must match the number of epochs exported"
        );
    }

    /// A parked by-ref self-Update is carried in the membership's
    /// `pending_updates` (spec/snapshot.md §4.1.2 key 1) instead of refusing
    /// the export: dense-indexed entries whose secret is the proposed leaf's
    /// HPKE private key.
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn export_for_swift_carries_pending_self_update() {
        let cipher_suite: CipherSuite = TEST_CIPHER_SUITE;
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, cipher_suite, 2).await;

        groups[0].propose_update(vec![]).await.unwrap();

        assert!(
            !groups[0].pending_updates.is_empty(),
            "the parked self-update must be in runtime state before export"
        );

        let bytes = groups[0].export_for_swift().await.unwrap();

        let value: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let top = value.into_map().expect("top level is a map");

        fn get(map: &[(Value, Value)], k: u64) -> &Value {
            map.iter()
                .find(|(key, _)| key == &Value::from(k))
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("missing key {k}"))
        }

        let membership = get(&top, 2).as_map().unwrap()[0].1.as_map().unwrap();

        let pending = get(membership, 1)
            .as_map()
            .expect("pending_updates present");
        assert_eq!(pending.len(), 1, "the parked self-update");

        let entry = pending[0].1.as_map().expect("PendingUpdateEntry");
        let public_key = get(entry, 0).as_bytes().expect("public_key bytes");
        let secret = get(entry, 1).as_bytes().expect("secret bytes");

        assert!(!public_key.is_empty());
        assert!(
            !secret.is_empty(),
            "the proposed leaf's private key is the whole point of carrying a pending update"
        );

        // Mutation check for this secret category (acceptance criterion 4):
        // corrupting the carried pending-update leaf secret is detected.
        use super::test_support::{flip_last_byte, value_at_mut, Step};

        let honest: Value = ciborium::from_reader(bytes.as_slice()).unwrap();
        let mut corrupted_archive = honest.clone();

        let target = value_at_mut(
            &mut corrupted_archive,
            &[
                Step::Key(2),
                Step::First,
                Step::Key(1),
                Step::First,
                Step::Key(1),
            ],
        )
        .expect("pending-update secret path resolves");

        assert!(flip_last_byte(target), "path ends on a byte string");

        let mut corrupted_bytes = Vec::new();
        ciborium::into_writer(&corrupted_archive, &mut corrupted_bytes).unwrap();

        assert_ne!(bytes, corrupted_bytes);

        let corrupted: Value = ciborium::from_reader(corrupted_bytes.as_slice()).unwrap();

        assert!(
            super::test_support::structural_diff(&honest, &corrupted),
            "the checker must detect the corrupted pending-update secret"
        );
    }

    /// A pending self-Update that also rotates the signing identity has no
    /// representation in the snapshot format (§2 excludes signature private
    /// keys), so export must refuse rather than silently drop the signer.
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn export_for_swift_refuses_pending_update_with_signer() {
        let cipher_suite: CipherSuite = TEST_CIPHER_SUITE;
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, cipher_suite, 2).await;

        let (identity, signer) = crate::identity::test_utils::get_test_signing_identity(
            TEST_CIPHER_SUITE,
            b"rotated identity",
        )
        .await;

        groups[0]
            .propose_update_with_identity(signer, identity, vec![])
            .await
            .unwrap();

        match groups[0].export_for_swift().await {
            Err(crate::client::MlsError::SwiftExportPendingUpdateSignerUnsupported) => (),
            other => panic!("expected signer refusal, got {other:?}"),
        }
    }

    /// Mutation check (acceptance criterion 4): corrupting an exported secret
    /// is detectable. Each corruption below targets a specific secret-bearing
    /// path in the decoded archive, then confirms the bytes changed and the
    /// decoded-state comparison flags the difference.
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn corrupted_exported_secret_is_detected() {
        let cipher_suite: CipherSuite = TEST_CIPHER_SUITE;
        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, cipher_suite, 2).await;

        let commit_output = groups[0].commit(vec![]).await.unwrap();
        groups[0].apply_pending_commit().await.unwrap();
        groups[1]
            .process_incoming_message(commit_output.commit_message)
            .await
            .unwrap();

        // Advance bob's send ratchet so the current epoch carries a chain
        // (the chain-head-secret corruption path needs one).
        let msg = groups[1]
            .encrypt_application_message(b"hello", vec![])
            .await
            .unwrap();
        groups[0].process_incoming_message(msg).await.unwrap();

        let bytes = groups[0].export_for_swift().await.unwrap();

        // Acceptance criterion 4: corrupt one exported secret at a time --
        // each path below ends on real key material in the decoded archive --
        // and confirm the corruption changes the bytes AND is detected by the
        // decoded-state comparison. A mapping that put a secret in the wrong
        // place (or dropped one) would leave one of these paths corrupting a
        // different value than intended, or going nowhere.
        use super::test_support::{flip_last_byte, structural_diff, value_at_mut, Step};

        let honest: Value = ciborium::from_reader(bytes.as_slice()).unwrap();

        let k = |n: u64| Step::Key(n);
        let paths: Vec<(&str, Vec<Step>)> = vec![
            (
                "exporter-tree frontier secret",
                vec![k(1), k(8), k(1), Step::First],
            ),
            ("epoch exporter_secret", vec![k(1), k(3), k(1)]),
            ("resumption psk", vec![k(1), k(4), Step::First]),
            (
                "chain head secret",
                vec![k(1), k(5), Step::Last, k(4), Step::First, k(1)],
            ),
            (
                "membership tree secret key (KEM)",
                vec![k(2), Step::First, k(0), Step::First],
            ),
        ];

        for (name, path) in paths {
            let mut corrupted_archive = honest.clone();
            let target = value_at_mut(&mut corrupted_archive, &path)
                .unwrap_or_else(|| panic!("{name}: path does not resolve"));

            assert!(
                flip_last_byte(target),
                "{name}: path does not end on a byte string"
            );

            let mut corrupted_bytes = Vec::new();
            ciborium::into_writer(&corrupted_archive, &mut corrupted_bytes).unwrap();

            assert_ne!(
                bytes, corrupted_bytes,
                "{name}: the mutation must change the exported bytes"
            );

            let corrupted: Value = ciborium::from_reader(corrupted_bytes.as_slice()).unwrap();

            assert!(
                structural_diff(&honest, &corrupted),
                "the checker must detect the corrupted {name}"
            );
        }

        assert!(
            !structural_diff(&honest, &honest),
            "the checker must accept an unmodified archive"
        );
    }

    /// The PQ half's guard (acceptance criterion 3): an ML-KEM-768 group keyed
    /// by the AWS-LC provider holds 2400-byte FIPS 203 expanded secrets, which
    /// swift-mls cannot reconstruct -- export must refuse with a clear error
    /// rather than ship a key that decodes cleanly and fails at first
    /// decapsulation. Needs the awslc provider (only crate besides cryptokit
    /// that speaks a PQ suite), hence the feature gate.
    #[cfg(feature = "benchmark_pq_crypto")]
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn export_refuses_non_cryptokit_ml_kem_secrets() {
        use crate::client::MlsError;
        use crate::client_builder::ClientBuilder;
        use crate::identity::{
            basic::{BasicCredential, BasicIdentityProvider},
            SigningIdentity,
        };
        use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};

        const ML_KEM_768: CipherSuite = CipherSuite::new(65002);

        let provider = mls_rs_crypto_awslc::AwsLcCryptoProvider::new();
        let cs = provider
            .cipher_suite_provider(ML_KEM_768)
            .expect("awslc supports ML_KEM_768 under benchmark_pq_crypto");

        let (signer, public_key) = cs.signature_key_generate().await.unwrap();

        let client = ClientBuilder::new()
            .crypto_provider(provider)
            .identity_provider(BasicIdentityProvider::new())
            .signing_identity(
                SigningIdentity::new(
                    BasicCredential::new(b"awslc pq".to_vec()).into_credential(),
                    public_key,
                ),
                signer,
                ML_KEM_768,
            )
            .build();

        let mut group = client
            .create_group_with_id(
                b"awslc-pq".to_vec(),
                Default::default(),
                Default::default(),
                None,
            )
            .await
            .unwrap();

        match group.export_for_swift().await {
            Err(MlsError::SwiftExportSecretKeyLengthMismatch { .. }) => (),
            other => panic!("expected PQ secret-key refusal, got {other:?}"),
        }
    }
}

/// Test-only helpers for the mutation checks.
#[cfg(test)]
mod test_support {
    use super::*;

    /// One navigation step through a decoded CBOR map: an integer map key,
    /// or "the first/last entry" (for maps keyed by dynamic values like
    /// epochs, leaves and node indices; epochs are ascending, so `Last` is
    /// the current epoch).
    #[derive(Clone, Copy)]
    pub enum Step {
        Key(u64),
        First,
        Last,
    }

    /// Resolves `steps` from the top of `value`, descending through maps.
    pub fn value_at_mut<'a>(value: &'a mut Value, steps: &[Step]) -> Option<&'a mut Value> {
        let mut cursor = value;

        for step in steps {
            let map = match cursor {
                Value::Map(entries) => entries,
                _ => return None,
            };

            cursor = match step {
                Step::Key(n) => map
                    .iter_mut()
                    .find(|(k, _)| k == &Value::from(*n))
                    .map(|(_, v)| v)?,
                Step::First => &mut map.first_mut()?.1,
                Step::Last => &mut map.last_mut()?.1,
            };
        }

        Some(cursor)
    }

    /// Flips the last byte of a byte-string value in place. Returns false if
    /// the value is not a non-empty byte string.
    pub fn flip_last_byte(value: &mut Value) -> bool {
        match value {
            Value::Bytes(b) if !b.is_empty() => {
                let last = b.len() - 1;
                b[last] ^= 0xFF;
                true
            }
            _ => false,
        }
    }

    /// Depth-first structural comparison of two decoded snapshots: true when
    /// they differ anywhere. The mutation tests' detector -- it is what a bad
    /// mapping (a secret in the wrong field, dropped, or swapped for another)
    /// would fail against the honest export.
    pub fn structural_diff(a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::Map(a_entries), Value::Map(b_entries)) => {
                if a_entries.len() != b_entries.len() {
                    return true;
                }

                a_entries
                    .iter()
                    .zip(b_entries.iter())
                    .any(|((ak, av), (bk, bv))| ak != bk || structural_diff(av, bv))
            }
            (Value::Bytes(a), Value::Bytes(b)) => a != b,
            (Value::Array(a), Value::Array(b)) => {
                a.len() != b.len() || a.iter().zip(b.iter()).any(|(x, y)| structural_diff(x, y))
            }
            _ => a != b,
        }
    }
}

/// GENERATOR, not a correctness test: running `generate_swift_migration_fixture`
/// overwrites `test_data/swift-migration-p256.json` (the classical-suite
/// format-2 fixture for the swift-mls migration). `#[ignore]`d so a plain
/// `cargo test` never dirties `test_data`; run it explicitly with
/// `cargo test -p mls-rs --features swift_export generate_swift_migration_fixture -- --ignored`.
#[cfg(test)]
mod fixture_gen {
    use serde::Serialize;

    use crate::{
        cipher_suite::CipherSuite,
        client::test_utils::TEST_PROTOCOL_VERSION,
        group::{test_utils::test_n_member_group, ReceivedMessage},
    };

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
        /// The exporter tree's surviving frontier, decoded back out of
        /// `export` for cross-checking (node index -> hex secret).
        exporter_frontier: Vec<(u32, String)>,
        export: String,
        messages: Vec<FixtureMessage>,
    }

    /// Builds a 2-member P256_AES128 group, has Bob encrypt one message in
    /// each of two epochs that Alice never processes, exports Alice's live
    /// state via `export_for_swift`, and -- only after confirming on a clone
    /// of Alice that her pre-migration state still decrypts both messages
    /// fresh -- writes the fixture a restored swift group can be tested
    /// against. A failing self-check panics instead of writing a fixture
    /// that would let a consuming (non-forward-secret) migration pass.
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    #[ignore]
    async fn generate_swift_migration_fixture() {
        let cipher_suite = CipherSuite::P256_AES128;

        let mut groups = test_n_member_group(TEST_PROTOCOL_VERSION, cipher_suite, 2).await;

        // Message A: prior epoch. Alice never processes it.
        let message_a = groups[1]
            .encrypt_application_message(b"prior-epoch hello", vec![])
            .await
            .unwrap();

        let epoch_a = groups[0].context().epoch;

        // Advance one epoch via an empty commit. Alice and Bob process only
        // the commit -- never messages A or B.
        let commit_output = groups[0].commit(vec![]).await.unwrap();
        groups[0].apply_pending_commit().await.unwrap();

        groups[1]
            .process_incoming_message(commit_output.commit_message)
            .await
            .unwrap();

        // Message B: current epoch. Alice never processes it.
        let message_b = groups[1]
            .encrypt_application_message(b"current-epoch hello", vec![])
            .await
            .unwrap();

        let epoch_b = groups[0].context().epoch;
        assert_eq!(
            epoch_b,
            epoch_a + 1,
            "epoch_b must be exactly one past epoch_a"
        );

        let export = groups[0].export_for_swift().await.unwrap();

        let exporter_frontier = decode_exporter_frontier(&export);

        // Self-check on a CLONE, so Alice's real (exported) state stays
        // unconsumed: prove her pre-migration state decrypts both the
        // prior-epoch and current-epoch message fresh.
        let mut alice_check = groups[0].clone();

        match alice_check
            .process_incoming_message(message_a.clone())
            .await
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
            .await
            .unwrap()
        {
            ReceivedMessage::ApplicationMessage(m) => assert_eq!(
                m.data(),
                b"current-epoch hello",
                "self-check: message B decrypted to unexpected plaintext"
            ),
            other => panic!("self-check: message B was not an application message: {other:?}"),
        }

        let fixture = Fixture {
            cipher_suite: u16::from(cipher_suite),
            exporter_leaf: 0,
            exporter_frontier,
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
            "/test_data/swift-migration-p256.json"
        );

        std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();

        std::eprintln!("wrote fixture to {path}");
    }

    /// Decodes the exported format-2 CBOR far enough to pull out the
    /// exporter-tree frontier (core key 8 -> node_secrets key 1), so the
    /// fixture carries it alongside the opaque export for slice-C
    /// cross-checking.
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
}
