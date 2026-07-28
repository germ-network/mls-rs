// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::vec::Vec;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use zeroize::Zeroizing;

use crate::{client::MlsError, tree_kem::node::NodeIndex, CipherSuiteProvider};

use super::component_operation::ComponentID;
use super::secret_tree::SecretTree;

/// The Exporter Tree of draft-ietf-mls-extensions-08 (Section 4.4, "Exported
/// Secrets"): a tree of secrets with the same structure and derivation as the
/// Secret Tree of RFC 9420 Section 9, except that it always has 2^16 leaves
/// and its root is the `application_export_secret` derived from the
/// `epoch_secret` with the label `"application_export"`.
///
/// `SafeExportSecret(ComponentID)` is the `tree_node_secret` at the leaf node
/// indexed by the ComponentID. Nodes are derived on demand with
/// `ExpandWithLabel(parent_secret, "tree", "left" | "right", KDF.Nh)` and
/// parents are deleted as soon as their children are derived, following the
/// deletion schedule in RFC 9420 Section 9.2. Once a component's secret has
/// been exported it is regarded as consumed and cannot be exported again in
/// the same epoch.
///
/// Note on the ComponentID range: draft-ietf-mls-extensions-08 defines
/// `uint32 ComponentID` while giving the Exporter Tree "2^16 leaves,
/// corresponding to the 16 bits of a ComponentID value"; draft -09 resolves
/// this inconsistency by narrowing ComponentID to `uint16`. We keep the u32
/// [`ComponentID`] type used elsewhere in this crate (matching -08) and reject
/// values that do not fit in the 2^16-leaf tree instead of truncating, which
/// would collide distinct components onto the same leaf.
#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct ExporterTree(SecretTree<NodeIndex>);

impl ExporterTree {
    pub const LEAF_COUNT: NodeIndex = 1 << 16;

    pub fn new(application_export_secret: Zeroizing<Vec<u8>>) -> Self {
        Self(SecretTree::new(Self::LEAF_COUNT, application_export_secret))
    }

    /// Placeholder for group states that do not have an
    /// `application_export_secret`, e.g. while building an external commit.
    pub fn empty() -> Self {
        Self(SecretTree::empty())
    }

    /// `SafeExportSecret(component_id)` from draft-ietf-mls-extensions-08
    /// Section 4.4.
    ///
    /// Returns the `tree_node_secret` at the leaf node for `component_id` and
    /// regards it as consumed: source key material is deleted according to
    /// the deletion schedule in RFC 9420 Section 9.2, and exporting the same
    /// component again in this epoch fails with
    /// [`MlsError::ComponentSecretConsumed`].
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn safe_export_secret<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        component_id: ComponentID,
    ) -> Result<Zeroizing<Vec<u8>>, MlsError> {
        self.0
            .take_leaf_secret(cipher_suite_provider, Self::leaf_index(component_id)?)
            .await
    }

    /// `SafeExportSecret(component_id)` without the consume semantics: the
    /// component's secret can be derived again for as long as the epoch's
    /// state is retained.
    ///
    /// This is what components need when a secret has to be re-derived from
    /// stored group state rather than held in memory — attachment content
    /// encryption keys, whose object references can arrive long after the
    /// epoch that produced them. It trades the deletion schedule of
    /// [`ExporterTree::safe_export_secret`] for that re-derivability, so a
    /// component should use one or the other, not both.
    ///
    /// Other components are unaffected either way: `consume_node` derives both
    /// children before dropping a parent, so a consuming export never strands
    /// a sibling subtree.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn peek_export_secret<P: CipherSuiteProvider>(
        &self,
        cipher_suite_provider: &P,
        component_id: ComponentID,
    ) -> Result<Zeroizing<Vec<u8>>, MlsError> {
        self.0
            .peek_leaf_secret(cipher_suite_provider, Self::leaf_index(component_id)?)
            .await
    }

    /// Delete a component's secret, making it underivable for the rest of the
    /// epoch. Idempotent.
    ///
    /// This is the consuming export with the result discarded: the deletion
    /// schedule pushes the frontier down past the component's leaf, so every
    /// other component stays exportable.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn delete_component_secret<P: CipherSuiteProvider>(
        &mut self,
        cipher_suite_provider: &P,
        component_id: ComponentID,
    ) -> Result<(), MlsError> {
        match self
            .safe_export_secret(cipher_suite_provider, component_id)
            .await
        {
            Ok(_) | Err(MlsError::ComponentSecretConsumed) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// The leaf for component id `c` is at node index `2 c` in the array
    /// representation of RFC 9420 Appendix C, the same mapping as
    /// `From<LeafIndex> for NodeIndex` (a ComponentID is not a member
    /// LeafIndex, so the typed conversion does not apply here).
    fn leaf_index(component_id: ComponentID) -> Result<NodeIndex, MlsError> {
        (component_id < Self::LEAF_COUNT)
            .then(|| component_id * 2)
            .ok_or(MlsError::InvalidComponentId)
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use zeroize::Zeroizing;

    use crate::client::MlsError;
    use crate::crypto::test_utils::try_test_cipher_suite_provider;
    use crate::group::key_schedule::kdf_expand_with_label;
    use crate::CipherSuiteProvider;

    use super::ExporterTree;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    const TEST_ROOT: [u8; 32] = [42u8; 32];

    fn test_tree() -> ExporterTree {
        ExporterTree::new(Zeroizing::new(TEST_ROOT.to_vec()))
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn component_ids_out_of_range_are_rejected() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let res = test_tree().safe_export_secret(&cs, 1 << 16).await;
        assert_matches!(res, Err(MlsError::InvalidComponentId));

        let res = test_tree().safe_export_secret(&cs, u32::MAX).await;
        assert_matches!(res, Err(MlsError::InvalidComponentId));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn empty_tree_is_rejected() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let res = ExporterTree::empty().safe_export_secret(&cs, 0).await;
        assert_matches!(res, Err(MlsError::ComponentSecretConsumed));

        let res = ExporterTree::empty().peek_export_secret(&cs, 0).await;
        assert_matches!(res, Err(MlsError::ComponentSecretConsumed));
    }

    /// The two accessors must agree: they are the same derivation, differing
    /// only in whether the path is deleted afterwards.
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn peek_matches_take_for_the_same_component() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        for component_id in [0, 1, 0x8000, 0xBEEF, 0xFFFF] {
            let peeked = test_tree()
                .peek_export_secret(&cs, component_id)
                .await
                .unwrap();

            let taken = test_tree()
                .safe_export_secret(&cs, component_id)
                .await
                .unwrap();

            assert_eq!(peeked, taken);
        }
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn peek_does_not_consume_and_is_rejected_out_of_range() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let tree = test_tree();
        let first = tree.peek_export_secret(&cs, 0x8000).await.unwrap();

        for _ in 0..4 {
            let repeat = tree.peek_export_secret(&cs, 0x8000).await.unwrap();
            assert_eq!(repeat, first);
        }

        // Peeking leaves the tree byte-identical, so it never changes the
        // serialized epoch state.
        assert_eq!(tree, test_tree());

        let res = tree.peek_export_secret(&cs, 1 << 16).await;
        assert_matches!(res, Err(MlsError::InvalidComponentId));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn peek_survives_consumption_of_other_components() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let mut tree = test_tree();
        let before = tree.peek_export_secret(&cs, 0x8000).await.unwrap();

        // Sibling leaf, far leaf, and a leaf sharing most of the path.
        for component_id in [0x8001, 0x0000, 0xFFFF, 0x8002] {
            tree.safe_export_secret(&cs, component_id).await.unwrap();
        }

        let after = tree.peek_export_secret(&cs, 0x8000).await.unwrap();
        assert_eq!(after, before);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn delete_component_secret_is_scoped_and_idempotent() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let mut tree = test_tree();
        let other = tree.peek_export_secret(&cs, 0x8001).await.unwrap();

        tree.delete_component_secret(&cs, 0x8000).await.unwrap();

        let res = tree.peek_export_secret(&cs, 0x8000).await;
        assert_matches!(res, Err(MlsError::ComponentSecretConsumed));

        tree.delete_component_secret(&cs, 0x8000).await.unwrap();

        let other_after = tree.peek_export_secret(&cs, 0x8001).await.unwrap();
        assert_eq!(other_after, other);

        let res = tree.delete_component_secret(&cs, 1 << 16).await;
        assert_matches!(res, Err(MlsError::InvalidComponentId));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn export_is_deterministic_and_domain_separated() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let a = test_tree().safe_export_secret(&cs, 0x8000).await.unwrap();
        let b = test_tree().safe_export_secret(&cs, 0x8000).await.unwrap();
        let c = test_tree().safe_export_secret(&cs, 0x8001).await.unwrap();

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), cs.kdf_extract_size());
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn export_consumes_the_component_secret() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let mut tree = test_tree();

        let first = tree.safe_export_secret(&cs, 3).await.unwrap();

        let res = tree.safe_export_secret(&cs, 3).await;
        assert_matches!(res, Err(MlsError::ComponentSecretConsumed));

        // Other components remain exportable and unchanged after consumption.
        let sibling = tree.safe_export_secret(&cs, 2).await.unwrap();
        let expected = test_tree().safe_export_secret(&cs, 2).await.unwrap();
        assert_eq!(sibling, expected);
        assert_ne!(first, sibling);
    }

    /// The leaf for component id 0 in a tree of 2^16 leaves is reached by
    /// sixteen `ExpandWithLabel(., "tree", "left", KDF.Nh)` expansions from
    /// the root, per the Secret Tree derivation of RFC 9420 Section 9.
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn component_zero_is_sixteen_left_expansions() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let mut expected = Zeroizing::new(TEST_ROOT.to_vec());

        for _ in 0..16 {
            expected = kdf_expand_with_label(&cs, &expected, b"tree", b"left", None)
                .await
                .unwrap();
        }

        let derived = test_tree().safe_export_secret(&cs, 0).await.unwrap();

        assert_eq!(derived, expected);
    }

    // Neither draft-ietf-mls-extensions-08 nor the interop repository defines
    // test vectors for SafeExportSecret yet. This known-answer test freezes
    // the derivation on cipher suite 1 (CURVE25519_AES128) so that accidental
    // changes to the tree walk are caught.
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn safe_export_secret_known_answer() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let secret = test_tree().safe_export_secret(&cs, 0x8000).await.unwrap();

        assert_eq!(
            hex::encode(&*secret),
            "ea8c3bd72ab7adcf2cc5a6aebe06ea77ef48001a695ec15eaf6a801f8573d853"
        );

        // The tree descent is equivalent to walking the 16 bits of the
        // component id from the most significant bit down, expanding with
        // "left" for a 0 bit and "right" for a 1 bit. For 0x8000 that is one
        // "right" expansion followed by fifteen "left" expansions.
        let mut expected = Zeroizing::new(TEST_ROOT.to_vec());

        expected = kdf_expand_with_label(&cs, &expected, b"tree", b"right", None)
            .await
            .unwrap();

        for _ in 0..15 {
            expected = kdf_expand_with_label(&cs, &expected, b"tree", b"left", None)
                .await
                .unwrap();
        }

        assert_eq!(secret, expected);
    }
}
