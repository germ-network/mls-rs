// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::vec::Vec;
use mls_rs_codec::{MlsEncode, MlsSize};
use zeroize::Zeroizing;

use crate::client::MlsError;
use crate::CipherSuiteProvider;

use super::component_operation::ComponentID;
use super::key_schedule::kdf_expand_with_label;

/// SEAL consumes a raw 32-byte content encryption key.
pub(crate) const ATTACHMENT_CEK_LEN: usize = 32;

/// `ComponentOperationLabel` as redefined by draft-ietf-mls-extensions-09:
///
/// ```text
/// struct {
///     opaque base_label<V> = "MLS Component";
///     uint16 component_id;
///     opaque label<V>;
/// } ComponentOperationLabel;
/// ```
///
/// This is a different structure from the older-draft
/// [`super::component_operation::ComponentOperationLabel`] (`"MLS 1.0
/// Application"` base label, `uint32` component id, trailing `context<V>`)
/// that the HPKE-based `safe_encrypt_with_context_*` APIs encode. The two
/// produce different bytes and must coexist.
///
/// `component_id` is narrowed to `uint16` here to match -09; callers reach
/// this through [`ExporterTree`](super::exporter_tree::ExporterTree), which
/// already rejects ids that do not fit the 2^16-leaf tree.
#[derive(MlsSize, MlsEncode)]
struct ComponentOperationLabel {
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    base_label: &'static [u8],
    component_id: u16,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    label: &'static [u8],
}

impl ComponentOperationLabel {
    fn for_attachment(component_id: u16) -> Self {
        Self {
            base_label: b"MLS Component",
            component_id,
            label: b"attachment",
        }
    }
}

/// Attachment content encryption key from draft-sullivan-mls-attachments:
///
/// ```text
/// CEK = ExpandWithLabel(SafeExportSecret(component_id),
///                       ComponentOperationLabel, object_id, 32)
/// ```
///
/// `component_secret` is `SafeExportSecret(component_id)`. `object_id` must be
/// between 1 and 255 bytes long.
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn attachment_cek<P: CipherSuiteProvider>(
    cipher_suite_provider: &P,
    component_secret: &[u8],
    component_id: ComponentID,
    object_id: &[u8],
) -> Result<Zeroizing<Vec<u8>>, MlsError> {
    if object_id.is_empty() || object_id.len() > 255 {
        return Err(MlsError::InvalidObjectId);
    }

    let component_id = u16::try_from(component_id).map_err(|_| MlsError::InvalidComponentId)?;
    let label = ComponentOperationLabel::for_attachment(component_id).mls_encode_to_vec()?;

    kdf_expand_with_label(
        cipher_suite_provider,
        component_secret,
        &label,
        object_id,
        Some(ATTACHMENT_CEK_LEN),
    )
    .await
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use assert_matches::assert_matches;
    use mls_rs_codec::MlsEncode;

    use crate::client::MlsError;
    use crate::crypto::test_utils::try_test_cipher_suite_provider;

    use super::{attachment_cek, ComponentOperationLabel, ATTACHMENT_CEK_LEN};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    const TEST_SECRET: [u8; 32] = [42u8; 32];

    #[test]
    fn component_operation_label_encoding() {
        let encoded = ComponentOperationLabel::for_attachment(0x0102)
            .mls_encode_to_vec()
            .unwrap();

        let expected = [
            &[0x0d][..],
            b"MLS Component",
            &[0x01, 0x02],
            &[0x0a],
            b"attachment",
        ]
        .concat();

        assert_eq!(encoded, expected);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn object_id_bounds_are_enforced() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let res = attachment_cek(&cs, &TEST_SECRET, 1, &[]).await;
        assert_matches!(res, Err(MlsError::InvalidObjectId));

        let res = attachment_cek(&cs, &TEST_SECRET, 1, &vec![0u8; 256]).await;
        assert_matches!(res, Err(MlsError::InvalidObjectId));

        let shortest = attachment_cek(&cs, &TEST_SECRET, 1, &[0u8]).await;
        assert!(shortest.is_ok());

        let longest = attachment_cek(&cs, &TEST_SECRET, 1, &vec![0u8; 255]).await;
        assert!(longest.is_ok());
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn cek_is_32_bytes_and_separated_by_component_and_object() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let base = attachment_cek(&cs, &TEST_SECRET, 1, b"object-a")
            .await
            .unwrap();
        assert_eq!(base.len(), ATTACHMENT_CEK_LEN);

        // The component id is bound through the label, the object id through
        // the ExpandWithLabel context.
        let other_component = attachment_cek(&cs, &TEST_SECRET, 2, b"object-a")
            .await
            .unwrap();
        let other_object = attachment_cek(&cs, &TEST_SECRET, 1, b"object-b")
            .await
            .unwrap();

        assert_ne!(base, other_component);
        assert_ne!(base, other_object);

        let repeat = attachment_cek(&cs, &TEST_SECRET, 1, b"object-a")
            .await
            .unwrap();
        assert_eq!(base, repeat);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn component_ids_out_of_range_are_rejected() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let res = attachment_cek(&cs, &TEST_SECRET, 1 << 16, b"object").await;
        assert_matches!(res, Err(MlsError::InvalidComponentId));
    }
}
