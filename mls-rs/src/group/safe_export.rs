// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use alloc::vec::Vec;
use mls_rs_codec::{MlsEncode, MlsSize};
use zeroize::Zeroizing;

use crate::client::MlsError;
use crate::CipherSuiteProvider;

use super::key_schedule::kdf_expand_with_label;

/// CEK length fixed at 32 bytes per draft-sullivan-mls-attachments (SEAL
/// consumes a raw 32-byte content encryption key).
pub(crate) const ATTACHMENT_CEK_LEN: usize = 32;

const COMPONENT_ID_BITS: u32 = u16::BITS;

/// `ComponentOperationLabel` from draft-ietf-mls-extensions:
///
/// ```text
/// struct {
///     opaque base_label<V> = "MLS Component";
///     uint16 component_id;
///     opaque label<V>;
/// } ComponentOperationLabel;
/// ```
///
/// This intentionally coexists with the older-draft
/// [`super::component_operation::ComponentOperationLabel`] (u32 component ids,
/// `"MLS 1.0 Application"` base label) used by the HPKE-based
/// `safe_encrypt_with_context_*` APIs.
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

/// `SafeExportSecret(component_id)` from draft-ietf-mls-extensions: walk the
/// exporter tree of depth 16 from `application_export_secret` at the root down
/// to the leaf indexed by `component_id`, deriving each child with
/// `ExpandWithLabel(parent, "tree", "left" | "right", KDF.Nh)` and branching on
/// the bits of `component_id`, most significant bit first.
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn safe_export_secret<P: CipherSuiteProvider>(
    cipher_suite_provider: &P,
    application_export_secret: &[u8],
    component_id: u16,
) -> Result<Zeroizing<Vec<u8>>, MlsError> {
    if application_export_secret.is_empty() {
        return Err(MlsError::ApplicationExportSecretDeleted);
    }

    let mut secret = Zeroizing::new(application_export_secret.to_vec());

    for bit in (0..COMPONENT_ID_BITS).rev() {
        let child: &[u8] = if component_id & (1 << bit) == 0 {
            b"left"
        } else {
            b"right"
        };

        secret =
            kdf_expand_with_label(cipher_suite_provider, &secret, b"tree", child, None).await?;
    }

    Ok(secret)
}

/// Attachment content encryption key from draft-sullivan-mls-attachments:
///
/// ```text
/// CEK = ExpandWithLabel(SafeExportSecret(component_id),
///                       ComponentOperationLabel, object_id, 32)
/// ```
///
/// `object_id` must be between 1 and 255 bytes long.
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn attachment_cek<P: CipherSuiteProvider>(
    cipher_suite_provider: &P,
    application_export_secret: &[u8],
    component_id: u16,
    object_id: &[u8],
) -> Result<Zeroizing<Vec<u8>>, MlsError> {
    if object_id.is_empty() || object_id.len() > 255 {
        return Err(MlsError::InvalidObjectId);
    }

    let component_secret = safe_export_secret(
        cipher_suite_provider,
        application_export_secret,
        component_id,
    )
    .await?;

    let label = ComponentOperationLabel::for_attachment(component_id).mls_encode_to_vec()?;

    kdf_expand_with_label(
        cipher_suite_provider,
        &component_secret,
        &label,
        object_id,
        Some(ATTACHMENT_CEK_LEN),
    )
    .await
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use mls_rs_codec::MlsEncode;

    use crate::client::MlsError;
    use crate::crypto::test_utils::try_test_cipher_suite_provider;
    use crate::group::key_schedule::kdf_expand_with_label;

    use super::{attachment_cek, safe_export_secret, ComponentOperationLabel};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    const TEST_ROOT: [u8; 32] = [42u8; 32];

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
    async fn deleted_root_is_rejected() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let res = safe_export_secret(&cs, &[], 0).await;
        assert_matches!(res, Err(MlsError::ApplicationExportSecretDeleted));

        let res = attachment_cek(&cs, &[], 0, b"object").await;
        assert_matches!(res, Err(MlsError::ApplicationExportSecretDeleted));
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn component_zero_is_sixteen_left_expansions() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let mut expected = zeroize::Zeroizing::new(TEST_ROOT.to_vec());

        for _ in 0..16 {
            expected = kdf_expand_with_label(&cs, &expected, b"tree", b"left", None)
                .await
                .unwrap();
        }

        let derived = safe_export_secret(&cs, &TEST_ROOT, 0).await.unwrap();

        assert_eq!(derived, expected);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn walk_is_deterministic_and_domain_separated() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let a = safe_export_secret(&cs, &TEST_ROOT, 0x8000).await.unwrap();
        let b = safe_export_secret(&cs, &TEST_ROOT, 0x8000).await.unwrap();
        let c = safe_export_secret(&cs, &TEST_ROOT, 0x8001).await.unwrap();

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn object_id_bounds() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let res = attachment_cek(&cs, &TEST_ROOT, 0, &[]).await;
        assert_matches!(res, Err(MlsError::InvalidObjectId));

        let res = attachment_cek(&cs, &TEST_ROOT, 0, &[0u8; 256]).await;
        assert_matches!(res, Err(MlsError::InvalidObjectId));

        let min = attachment_cek(&cs, &TEST_ROOT, 0, &[0u8; 1]).await.unwrap();
        let max = attachment_cek(&cs, &TEST_ROOT, 0, &[0u8; 255])
            .await
            .unwrap();

        assert_eq!(min.len(), 32);
        assert_eq!(max.len(), 32);
        assert_ne!(min, max);
    }

    // draft-sullivan-mls-attachments defines no official test vectors yet.
    // This known-answer test freezes the derivation on cipher suite 1
    // (CURVE25519_AES128) so that accidental changes are caught.
    #[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
    async fn attachment_cek_known_answer() {
        let Some(cs) = try_test_cipher_suite_provider(1) else {
            return;
        };

        let cek = attachment_cek(&cs, &TEST_ROOT, 0x8000, b"object-id")
            .await
            .unwrap();

        assert_eq!(
            hex::encode(&*cek),
            "ab3c7007ee43da89fcdb736ddc3a9953e7d952083b5afe6088a1e66299b9864b"
        );
    }
}
