// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use std::{
    collections::HashMap,
    io::{Cursor, Read, Seek, SeekFrom},
};

use async_generic::async_generic;
use log::error;

use crate::{
    assertion::{Assertion, AssertionData, AssertionDecodeError, AssertionDecodeErrorCause},
    assertions::{
        labels::{self, CLAIM},
        DataBox, DataHash,
    },
    asset_io::{
        CAIRead, CAIReadWrite, HashBlockObjectType, HashObjectPositions, RemoteRefEmbedType,
    },
    claim::{Claim, ClaimAssertion, ClaimAssetData, RemoteManifest},
    cose_sign::{cose_sign, cose_sign_async},
    cose_validator::{check_ocsp_status, verify_cose, verify_cose_async},
    error::{Error, Result},
    external_manifest::ManifestPatchCallback,
    hash_utils::{hash_by_alg, vec_compare},
    jumbf::{
        self,
        boxes::*,
        labels::{to_absolute_uri, ASSERTIONS, CREDENTIALS, DATABOXES, SIGNATURE},
    },
    jumbf_io::{
        get_assetio_handler, load_jumbf_from_stream, object_locations_from_stream,
        save_jumbf_to_stream,
    },
    salt::DefaultSalt,
    settings::get_settings_value,
    status_tracker::{log_item, DetailedStatusTracker, OneShotStatusTracker, StatusTracker},
    trust_handler::TrustHandlerConfig,
    utils::{
        hash_utils::{hash_sha256, HashRange},
        patch::patch_bytes,
    },
    validation_status, AsyncSigner, RemoteSigner, Signer,
};

const MANIFEST_STORE_EXT: &str = "c2pa"; // file extension for external manifests

/// A `Store` maintains a list of `Claim` structs.
///
/// Typically, this list of `Claim`s represents all of the claims in an asset.
#[derive(Debug)]
pub struct Store {
    claims_map: HashMap<String, usize>,
    manifest_box_hash_cache: HashMap<String, Vec<u8>>,
    claims: Vec<Claim>,
    label: String,
    provenance_path: Option<String>,
    trust_handler: Box<dyn TrustHandlerConfig>,
}

struct ManifestInfo<'a> {
    pub desc_box: &'a JUMBFDescriptionBox,
    pub sbox: &'a JUMBFSuperBox,
}

trait PushGetIndex {
    type Item;
    fn push_get_index(&mut self, item: Self::Item) -> usize;
}

impl<T> PushGetIndex for Vec<T> {
    type Item = T;

    fn push_get_index(&mut self, item: T) -> usize {
        let index = self.len();
        self.push(item);
        index
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    /// Create a new, empty claims store.
    pub fn new() -> Self {
        Self::new_with_label(MANIFEST_STORE_EXT)
    }

    /// Create a new, empty claims store with a custom label.
    ///
    /// In most cases, calling [`Store::new()`] is preferred.
    pub fn new_with_label(label: &str) -> Self {
        let mut store = Store {
            claims_map: HashMap::new(),
            manifest_box_hash_cache: HashMap::new(),
            claims: Vec::new(),
            label: label.to_string(),
            #[cfg(feature = "openssl")]
            trust_handler: Box::new(crate::openssl::OpenSSLTrustHandlerConfig::new()),
            #[cfg(all(not(feature = "openssl"), target_arch = "wasm32"))]
            trust_handler: Box::new(crate::wasm::WebTrustHandlerConfig::new()),
            #[cfg(all(not(feature = "openssl"), not(target_arch = "wasm32")))]
            trust_handler: Box::new(crate::trust_handler::TrustPassThrough::new()),
            provenance_path: None,
        };

        // load the trust handler settings, don't worry about status as these are
        // checked during setting generation
        let _ = get_settings_value::<Option<String>>("trust.trust_anchors").map(|ta_opt| {
            if let Some(ta) = ta_opt {
                let _v = store.add_trust(ta.as_bytes());
            }
        });

        let _ = get_settings_value::<Option<String>>("trust.private_anchors").map(|pa_opt| {
            if let Some(pa) = pa_opt {
                let _v = store.add_private_trust_anchors(pa.as_bytes());
            }
        });

        let _ = get_settings_value::<Option<String>>("trust.trust_config").map(|tc_opt| {
            if let Some(tc) = tc_opt {
                let _v = store.add_trust_config(tc.as_bytes());
            }
        });

        let _ = get_settings_value::<Option<String>>("trust.allowed_list").map(|al_opt| {
            if let Some(al) = al_opt {
                let _v = store.add_trust_allowed_list(al.as_bytes());
            }
        });

        store
    }

    /// Return label for the store
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Load set of trust anchors used for certificate validation. [u8]
    /// containing the trust anchors is passed in the trust_vec variable.
    pub fn add_trust(&mut self, trust_vec: &[u8]) -> Result<()> {
        let mut trust_reader = Cursor::new(trust_vec);
        self.trust_handler
            .load_trust_anchors_from_data(&mut trust_reader)
    }

    // Load set of private trust anchors used for certificate validation. [u8] to
    // the
    /// private trust anchors is passed in the trust_vec variable.  This can be
    /// called multiple times if there are additional trust stores.
    pub fn add_private_trust_anchors(&mut self, trust_vec: &[u8]) -> Result<()> {
        let mut trust_reader = Cursor::new(trust_vec);
        self.trust_handler
            .append_private_trust_data(&mut trust_reader)
    }

    pub fn add_trust_config(&mut self, trust_vec: &[u8]) -> Result<()> {
        let mut trust_reader = Cursor::new(trust_vec);
        self.trust_handler.load_configuration(&mut trust_reader)
    }

    pub fn add_trust_allowed_list(&mut self, allowed_vec: &[u8]) -> Result<()> {
        let mut trust_reader = Cursor::new(allowed_vec);
        self.trust_handler.load_allowed_list(&mut trust_reader)
    }

    /// Clear all existing trust anchors
    pub fn clear_trust_anchors(&mut self) {
        self.trust_handler.clear();
    }

    fn trust_handler(&self) -> &dyn TrustHandlerConfig {
        self.trust_handler.as_ref()
    }

    /// Get the provenance if available.
    /// If loaded from an existing asset it will be provenance from the last
    /// claim. If a new claim is committed that will be the provenance claim
    pub fn provenance_path(&self) -> Option<String> {
        if self.provenance_path.is_none() {
            // if we have claims and no provenance, return last claim
            if let Some(claim) = self.claims.last() {
                return Some(Claim::to_claim_uri(claim.label()));
            }
        }
        self.provenance_path.as_ref().cloned()
    }

    // set the path of the current provenance claim
    fn set_provenance_path(&mut self, claim_label: &str) {
        let path = Claim::to_claim_uri(claim_label);
        self.provenance_path = Some(path);
    }

    /// get the list of claims for this store
    pub fn claims(&self) -> &Vec<Claim> {
        &self.claims
    }

    /// the JUMBF manifest box hash (spec 1.2)
    pub fn get_manifest_box_hash(&self, claim: &Claim) -> Vec<u8> {
        if let Some(bh) = self.manifest_box_hash_cache.get(claim.label()) {
            bh.clone()
        } else {
            Store::calc_manifest_box_hash(claim, None, claim.alg()).unwrap_or_default()
        }
    }

    /// Add a new Claim to this Store. The function
    /// will return the label of the claim.
    pub fn commit_claim(&mut self, mut claim: Claim) -> Result<String> {
        // make sure there is no pending unsigned claim
        if let Some(pc) = self.provenance_claim() {
            if pc.signature_val().is_empty() {
                return Err(Error::ClaimUnsigned);
            }
        }
        // verify the claim is valid
        claim.build()?;

        // load the claim ingredients
        // parse first to make sure we can load them
        let mut ingredient_claims: Vec<Claim> = Vec::new();
        for (pc, claims) in claim.claim_ingredient_store() {
            let mut valid_pc = false;

            // expand for flat list insertion
            for ingredient_claim in claims {
                // recreate claim from original bytes
                let claim_clone = ingredient_claim.clone();
                if pc == claim_clone.label() {
                    valid_pc = true;
                }
                ingredient_claims.push(claim_clone);
            }
            if !valid_pc {
                return Err(Error::IngredientNotFound);
            }
        }

        // update the provenance path
        self.set_provenance_path(claim.label());

        let claim_label = claim.label().to_string();

        // insert ingredients if needed
        for ingredient_claim in ingredient_claims {
            let label = ingredient_claim.label().to_owned();

            if let std::collections::hash_map::Entry::Vacant(e) = self.claims_map.entry(label) {
                let index = self.claims.push_get_index(ingredient_claim);
                e.insert(index);
            }
        }

        // add claim to store after ingredients
        let index = self.claims.push_get_index(claim);
        self.claims_map.insert(claim_label.clone(), index);

        Ok(claim_label)
    }

    /// Get Claim by label
    // Returns Option<&Claim>
    pub fn get_claim(&self, label: &str) -> Option<&Claim> {
        #![allow(clippy::unwrap_used)] // since it's only in a debug_assert
        let index = self.claims_map.get(label)?;
        debug_assert!(self.claims.get(*index).unwrap().label() == label);
        self.claims.get(*index)
    }

    /// Get Claim by label
    // Returns Option<&Claim>
    pub fn get_claim_mut(&mut self, label: &str) -> Option<&mut Claim> {
        #![allow(clippy::unwrap_used)] // since it's only in a debug_assert
        let index = self.claims_map.get(label)?;
        debug_assert!(self.claims.get(*index).unwrap().label() == label);
        self.claims.get_mut(*index)
    }

    /// returns a Claim given a jumbf uri
    pub fn get_claim_from_uri(&self, uri: &str) -> Result<&Claim> {
        let claim_label = Store::manifest_label_from_path(uri);
        self.get_claim(&claim_label)
            .ok_or_else(|| Error::ClaimMissing {
                label: claim_label.to_owned(),
            })
    }

    /// returns a ClaimAssertion given a jumbf uri, resolving to the right claim
    /// in the store
    pub fn get_claim_assertion_from_uri(&self, uri: &str) -> Result<&ClaimAssertion> {
        // first find the right claim and then look for the assertion there
        let claim = self.get_claim_from_uri(uri)?;
        let (label, instance) = Claim::assertion_label_from_link(uri);
        claim
            .get_claim_assertion(&label, instance)
            .ok_or_else(|| Error::ClaimMissing {
                label: label.to_owned(),
            })
    }

    /// Returns an Assertion referenced by JUMBF URI.  The URI should be
    /// absolute and include the desired Claim in the path. If you need to
    /// specify the Claim for this URI use get_assertion_from_uri_and_claim.
    /// uri - The JUMBF URI for desired Assertion.
    pub fn get_assertion_from_uri(&self, uri: &str) -> Option<&Assertion> {
        let claim_label = Store::manifest_label_from_path(uri);
        let (assertion_label, instance) = Claim::assertion_label_from_link(uri);

        if let Some(claim) = self.get_claim(&claim_label) {
            claim.get_assertion(&assertion_label, instance)
        } else {
            None
        }
    }

    /// Returns an Assertion referenced by JUMBF URI. Only the Claim specified
    /// by target_claim_label will be searched.  The target_claim_label can
    /// be a Claim label or JUMBF URI. uri - The JUMBF URI for desired
    /// Assertion. target_claim_label - Label or URI of the Claim to search
    /// for the case when the URI is a relative path.
    pub fn get_assertion_from_uri_and_claim(
        &self,
        uri: &str,
        target_claim_label: &str,
    ) -> Option<&Assertion> {
        let (assertion_label, instance) = Claim::assertion_label_from_link(uri);

        let label = Store::manifest_label_from_path(target_claim_label);

        if let Some(claim) = self.get_claim(&label) {
            claim.get_assertion(&assertion_label, instance)
        } else {
            None
        }
    }

    /// Returns a DataBox referenced by JUMBF URI if it exists.
    ///
    /// Relative paths will use the provenance claim to resolve the DataBox.d
    pub fn get_data_box_from_uri_and_claim(
        &self,
        uri: &str,
        target_claim_label: &str,
    ) -> Option<&DataBox> {
        match jumbf::labels::manifest_label_from_uri(uri) {
            Some(label) => self.get_claim(&label), // use the manifest label from the thumbnail uri
            None => self.get_claim(target_claim_label), //  relative so use the target claim label
        }
        .and_then(|claim| {
            let uri = if target_claim_label != self.label() {
                to_absolute_uri(target_claim_label, uri)
            } else {
                uri.to_owned()
            };
            claim
                .databoxes()
                .iter()
                .find(|(h, _d)| h.url() == uri)
                .map(|(_sh, data_box)| data_box)
        })
    }

    // Returns placeholder that will be searched for and replaced
    // with actual signature data.
    fn sign_claim_placeholder(claim: &Claim, min_reserve_size: usize) -> Vec<u8> {
        let placeholder_str = format!("signature placeholder:{}", claim.label());
        let mut placeholder = hash_sha256(placeholder_str.as_bytes());

        use std::cmp::max;
        placeholder.resize(max(placeholder.len(), min_reserve_size), 0);

        placeholder
    }

    //     /// Return certificate chain for the provenance claim
    //     #[cfg(feature = "v1_api")]
    //     pub(crate) fn get_provenance_cert_chain(&self) -> Result<String> {
    //         let claim = self.provenance_claim().ok_or(Error::ProvenanceMissing)?;
    //
    //         match claim.get_cert_chain() {
    //             Ok(chain) => String::from_utf8(chain).map_err(|_e|
    // Error::CoseInvalidCert),             Err(e) => Err(e),
    //         }
    //     }

    /// Return OCSP info if available
    // Currently only called from manifest_store behind a feature flag but this is allowable
    // anywhere so allow dead code here for future uses to compile
    #[allow(dead_code)]
    pub(crate) fn get_ocsp_status(&self) -> Option<String> {
        let claim = self
            .provenance_claim()
            .ok_or(Error::ProvenanceMissing)
            .ok()?;

        let sig = claim.signature_val();
        let data = claim.data().ok()?;
        let mut validation_log = OneShotStatusTracker::new();

        if let Ok(info) = check_ocsp_status(sig, &data, self.trust_handler(), &mut validation_log) {
            if let Some(revoked_at) = &info.revoked_at {
                Some(format!(
                    "Certificate Status: Revoked, revoked at: {}",
                    revoked_at
                ))
            } else {
                Some(format!(
                    "Certificate Status: Good, next update: {}",
                    info.next_update
                ))
            }
        } else {
            None
        }
    }

    /// Sign the claim and return signature.
    #[async_generic(async_signature(
        &self,
        claim: &Claim,
        signer: &dyn AsyncSigner,
        box_size: usize,
    ))]
    pub fn sign_claim(
        &self,
        claim: &Claim,
        signer: &dyn Signer,
        box_size: usize,
    ) -> Result<Vec<u8>> {
        let claim_bytes = claim.data()?;

        let result =
            if _sync {
                if signer.direct_cose_handling() {
                    // Let the signer do all the COSE processing and return the structured COSE
                    // data.
                    return signer.sign(&claim_bytes); // do not verify remote
                                                      // signers (we never did)
                } else {
                    cose_sign(signer, &claim_bytes, Some(box_size))
                }
            } else {
                if signer.direct_cose_handling() {
                    // Let the signer do all the COSE processing and return the structured COSE
                    // data.
                    return signer.sign(claim_bytes.clone()).await; // do not verify remote signers (we never did)
                } else {
                    cose_sign_async(signer, &claim_bytes, Some(box_size)).await
                }
            };
        match result {
            Ok(sig) => {
                // Sanity check: Ensure that this signature is valid.
                if let Ok(verify_after_sign) =
                    get_settings_value::<bool>("verify.verify_after_sign")
                {
                    if verify_after_sign {
                        let mut cose_log = OneShotStatusTracker::new();

                        let result = if _sync {
                            verify_cose(
                                &sig,
                                &claim_bytes,
                                b"",
                                false,
                                self.trust_handler(),
                                &mut cose_log,
                            )
                        } else {
                            verify_cose_async(
                                sig.clone(),
                                claim_bytes,
                                b"".to_vec(),
                                false,
                                self.trust_handler(),
                                &mut cose_log,
                            )
                            .await
                        };
                        if let Err(err) = result {
                            error!(
                                "Signature that was just generated does not validate: {:#?}",
                                err
                            );
                            return Err(err);
                        }
                    }
                }
                Ok(sig)
            }
            Err(e) => Err(e),
        }
    }

    /// return the current provenance claim label if available
    pub fn provenance_label(&self) -> Option<String> {
        self.provenance_path()
            .map(|provenance| Store::manifest_label_from_path(&provenance))
    }

    /// return the current provenance claim if available
    pub fn provenance_claim(&self) -> Option<&Claim> {
        match self.provenance_path() {
            Some(provenance) => {
                let claim_label = Store::manifest_label_from_path(&provenance);
                self.get_claim(&claim_label)
            }
            None => None,
        }
    }

    /// return the current provenance claim as mutable if available
    pub fn provenance_claim_mut(&mut self) -> Option<&mut Claim> {
        match self.provenance_path() {
            Some(provenance) => {
                let claim_label = Store::manifest_label_from_path(&provenance);
                self.get_claim_mut(&claim_label)
            }
            None => None,
        }
    }

    // add a restored claim
    fn insert_restored_claim(&mut self, label: String, claim: Claim) {
        let index = self.claims.push_get_index(claim);
        self.claims_map.insert(label, index);
    }

    fn add_assertion_to_jumbf_store(
        store: &mut CAIAssertionStore,
        claim_assertion: &ClaimAssertion,
    ) -> Result<()> {
        // Grab assertion data object.
        let d = claim_assertion.assertion().decode_data();

        match d {
            AssertionData::Json(_) => {
                let mut json_data = CAIJSONAssertionBox::new(&claim_assertion.label());
                json_data.add_json(claim_assertion.assertion().data().to_vec());
                if let Some(salt) = claim_assertion.salt() {
                    json_data.set_salt(salt.clone())?;
                }
                store.add_assertion(Box::new(json_data));
            }
            AssertionData::Binary(_) => {
                // TODO: Handle other binary box types if needed.
                let mut data = JumbfEmbeddedFileBox::new(&claim_assertion.label());
                data.add_data(
                    claim_assertion.assertion().data().to_vec(),
                    claim_assertion.assertion().mime_type(),
                    None,
                );
                if let Some(salt) = claim_assertion.salt() {
                    data.set_salt(salt.clone())?;
                }
                store.add_assertion(Box::new(data));
            }
            AssertionData::Cbor(_) => {
                let mut cbor_data = CAICBORAssertionBox::new(&claim_assertion.label());
                cbor_data.add_cbor(claim_assertion.assertion().data().to_vec());
                if let Some(salt) = claim_assertion.salt() {
                    cbor_data.set_salt(salt.clone())?;
                }
                store.add_assertion(Box::new(cbor_data));
            }
            AssertionData::Uuid(s, _) => {
                let mut uuid_data = CAIUUIDAssertionBox::new(&claim_assertion.label());
                uuid_data.add_uuid(s, claim_assertion.assertion().data().to_vec())?;
                if let Some(salt) = claim_assertion.salt() {
                    uuid_data.set_salt(salt.clone())?;
                }
                store.add_assertion(Box::new(uuid_data));
            }
        }
        Ok(())
    }

    // look for old style hashing to determine if this is a pre 1.0 claim
    fn is_old_assertion(alg: &str, data: &[u8], original_hash: &[u8]) -> bool {
        let old_hash = hash_by_alg(alg, data, None);
        vec_compare(&old_hash, original_hash)
    }

    fn get_assertion_from_jumbf_store(
        claim: &Claim,
        assertion_box: &JUMBFSuperBox,
        label: &str,
        check_for_legacy_assertion: bool,
    ) -> Result<ClaimAssertion> {
        let assertion_desc_box = assertion_box.desc_box();

        let (raw_label, instance) = Claim::assertion_label_from_link(label);
        let instance_label = Claim::label_with_instance(&raw_label, instance);
        let assertion_hashed_uri = claim
            .assertion_hashed_uri_from_label(&instance_label)
            .ok_or_else(|| {
                Error::AssertionDecoding(AssertionDecodeError {
                    label: instance_label.to_string(),
                    version: None, // TODO: Plumb this through
                    content_type: "TO DO: Get content type".to_string(),
                    source: AssertionDecodeErrorCause::AssertionDataIncorrect,
                })
            })?;

        let alg = match assertion_hashed_uri.alg() {
            Some(ref a) => a.clone(),
            None => claim.alg().to_string(),
        };

        // get salt value if set
        let salt = assertion_desc_box.get_salt();

        let result = match assertion_desc_box.uuid().as_ref() {
            CAI_JSON_ASSERTION_UUID => {
                let json_box = assertion_box
                    .data_box_as_json_box(0)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let assertion = Assertion::from_data_json(&raw_label, json_box.json())?;
                let hash = Claim::calc_assertion_box_hash(label, &assertion, salt.clone(), &alg)?;
                Ok(ClaimAssertion::new(assertion, instance, &hash, &alg, salt))
            }
            CAI_EMBEDDED_FILE_UUID => {
                let ef_box = assertion_box
                    .data_box_as_embedded_media_type_box(0)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let data_box = assertion_box
                    .data_box_as_embedded_file_content_box(1)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let media_type = ef_box.media_type();
                let assertion =
                    Assertion::from_data_binary(&raw_label, &media_type, data_box.data());
                let hash = Claim::calc_assertion_box_hash(label, &assertion, salt.clone(), &alg)?;
                Ok(ClaimAssertion::new(assertion, instance, &hash, &alg, salt))
            }
            CAI_CBOR_ASSERTION_UUID => {
                let cbor_box = assertion_box
                    .data_box_as_cbor_box(0)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let assertion = Assertion::from_data_cbor(&raw_label, cbor_box.cbor());
                let hash = Claim::calc_assertion_box_hash(label, &assertion, salt.clone(), &alg)?;
                Ok(ClaimAssertion::new(assertion, instance, &hash, &alg, salt))
            }
            CAI_UUID_ASSERTION_UUID => {
                let uuid_box = assertion_box
                    .data_box_as_uuid_box(0)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let uuid_str = hex::encode(uuid_box.uuid());
                let assertion = Assertion::from_data_uuid(&raw_label, &uuid_str, uuid_box.data());

                let hash = Claim::calc_assertion_box_hash(label, &assertion, salt.clone(), &alg)?;
                Ok(ClaimAssertion::new(assertion, instance, &hash, &alg, salt))
            }
            _ => Err(Error::JumbfCreationError),
        };

        if check_for_legacy_assertion {
            // make sure this is not pre 1.0 data
            match result {
                Ok(r) => {
                    // look for old style hashing
                    if Store::is_old_assertion(
                        &alg,
                        r.assertion().data(),
                        &assertion_hashed_uri.hash(),
                    ) {
                        Err(Error::PrereleaseError)
                    } else {
                        Ok(r)
                    }
                }
                Err(e) => Err(e),
            }
        } else {
            result
        }
    }

    /// Convert this claims store to a JUMBF box.
    pub fn to_jumbf(&self, signer: &dyn Signer) -> Result<Vec<u8>> {
        self.to_jumbf_internal(signer.reserve_size())
    }

    /// Convert this claims store to a JUMBF box.
    pub fn to_jumbf_async(&self, signer: &dyn AsyncSigner) -> Result<Vec<u8>> {
        self.to_jumbf_internal(signer.reserve_size())
    }

    fn to_jumbf_internal(&self, min_reserve_size: usize) -> Result<Vec<u8>> {
        // Create the CAI block.
        let mut cai_block = Cai::new();

        // Add claims and assertions in this store to the JUMBF store.
        for claim in &self.claims {
            let cai_store = Store::build_manifest_box(claim, min_reserve_size)?;

            // add the completed CAI store into the CAI block.
            cai_block.add_box(Box::new(cai_store));
        }

        // Write it to memory.
        let mut mem_box: Vec<u8> = Vec::new();
        cai_block.write_box(&mut mem_box)?;

        if mem_box.is_empty() {
            Err(Error::JumbfCreationError)
        } else {
            Ok(mem_box)
        }
    }

    fn build_manifest_box(claim: &Claim, min_reserve_size: usize) -> Result<CAIStore> {
        // box label
        let label = claim.label();

        let mut cai_store = CAIStore::new(label, claim.update_manifest());

        for manifest_box in claim.get_box_order() {
            match *manifest_box {
                ASSERTIONS => {
                    let mut a_store = CAIAssertionStore::new();

                    // add assertions to CAI assertion store.
                    let cas = claim.claim_assertion_store();
                    for assertion in cas {
                        Store::add_assertion_to_jumbf_store(&mut a_store, assertion)?;
                    }

                    cai_store.add_box(Box::new(a_store)); // add the assertion
                                                          // store to the
                                                          // manifest
                }
                CLAIM => {
                    let mut cb = CAIClaimBox::new();

                    // Add the Claim json
                    let claim_cbor_bytes = claim.data()?;
                    let c_cbor = JUMBFCBORContentBox::new(claim_cbor_bytes);
                    cb.add_claim(Box::new(c_cbor));

                    cai_store.add_box(Box::new(cb)); // add claim to manifest
                }
                SIGNATURE => {
                    // create a signature and add placeholder data to the CAI store.
                    let mut sigb = CAISignatureBox::new();
                    let signed_data = match claim.signature_val().is_empty() {
                        false => claim.signature_val().clone(), // existing claims have sig values
                        true => Store::sign_claim_placeholder(claim, min_reserve_size), /* empty is the new sig to be replaced */
                    };

                    let sigc = JUMBFCBORContentBox::new(signed_data);
                    sigb.add_signature(Box::new(sigc));

                    cai_store.add_box(Box::new(sigb)); // add signature to
                                                       // manifest
                }
                CREDENTIALS => {
                    // add vc_store if needed
                    if !claim.get_verifiable_credentials().is_empty() {
                        let mut vc_store = CAIVerifiableCredentialStore::new();

                        // Add assertions to CAI assertion store.
                        let vcs = claim.get_verifiable_credentials_store();
                        for (uri, assertion_data) in vcs {
                            if let AssertionData::Json(j) = assertion_data {
                                let id = Claim::vc_id(j)?;
                                let mut json_data = CAIJSONAssertionBox::new(&id);
                                json_data.add_json(j.as_bytes().to_vec());

                                if let Some(salt) = uri.salt() {
                                    json_data.set_salt(salt.clone())?;
                                }

                                vc_store.add_credential(Box::new(json_data));
                            } else {
                                return Err(Error::BadParam("VC data must be JSON".to_string()));
                            }
                        }
                        cai_store.add_box(Box::new(vc_store)); // add the CAI
                                                               // assertion store
                                                               // to manifest
                    }
                }
                DATABOXES => {
                    // Add the data boxes
                    if !claim.databoxes().is_empty() {
                        let mut databoxes = CAIDataboxStore::new();

                        for (uri, db) in claim.databoxes() {
                            let db_cbor_bytes =
                                serde_cbor::to_vec(db).map_err(|_err| Error::AssertionEncoding)?;

                            let (link, instance) = Claim::assertion_label_from_link(&uri.url());
                            let label = Claim::label_with_instance(&link, instance);

                            let mut db_cbor = CAICBORAssertionBox::new(&label);
                            db_cbor.add_cbor(db_cbor_bytes);

                            if let Some(salt) = uri.salt() {
                                db_cbor.set_salt(salt.clone())?;
                            }

                            databoxes.add_databox(Box::new(db_cbor));
                        }

                        cai_store.add_box(Box::new(databoxes)); // add claim to
                                                                // manifest
                    }
                }
                _ => return Err(Error::ClaimInvalidContent),
            }
        }

        Ok(cai_store)
    }

    // calculate the hash of the manifest JUMBF box
    pub fn calc_manifest_box_hash(
        claim: &Claim,
        salt: Option<Vec<u8>>,
        alg: &str,
    ) -> Result<Vec<u8>> {
        let mut hash_bytes = Vec::with_capacity(4096);

        // build box
        let mut cai_store = Store::build_manifest_box(claim, 0)?;

        // add salt if requested
        if let Some(salt) = salt {
            cai_store.set_salt(salt)?;
        }

        // box content as Vec
        cai_store.super_box().write_box_payload(&mut hash_bytes)?;

        Ok(hash_by_alg(alg, &hash_bytes, None))
    }

    fn manifest_map<'a>(sb: &'a JUMBFSuperBox) -> Result<HashMap<String, ManifestInfo<'a>>> {
        let mut box_info: HashMap<String, ManifestInfo<'a>> = HashMap::new();
        for i in 0..sb.data_box_count() {
            let sbox = sb.data_box_as_superbox(i).ok_or(Error::JumbfBoxNotFound)?;
            let desc_box = sbox.desc_box();

            let label = desc_box.uuid();

            let mi = ManifestInfo { desc_box, sbox };

            box_info.insert(label, mi);
        }

        Ok(box_info)
    }

    // Compare two version labels
    // base_version_label - is the source label
    // desired_version_label - is the label to compare to the base
    // returns true if desired version is <= base version
    fn check_label_version(base_version_label: &str, desired_version_label: &str) -> bool {
        if let Some(desired_version) = labels::version(desired_version_label) {
            if let Some(base_version) = labels::version(base_version_label) {
                if desired_version > base_version {
                    return false;
                }
            }
        }
        true
    }

    pub fn from_jumbf(buffer: &[u8], validation_log: &mut impl StatusTracker) -> Result<Store> {
        if buffer.is_empty() {
            return Err(Error::JumbfNotFound);
        }

        let mut store = Store::new();

        // setup a cursor for reading the buffer...
        let mut buf_reader = Cursor::new(buffer);

        // this loads up all the boxes...
        let super_box = BoxReader::read_super_box(&mut buf_reader)?;

        // this loads up all the boxes...
        let cai_block = Cai::from(super_box);

        // check the CAI Block
        let desc_box = cai_block.desc_box();
        if desc_box.uuid() != CAI_BLOCK_UUID {
            let log_item = log_item!("JUMBF", "c2pa box not found", "from_jumbf")
                .error(Error::InvalidClaim(InvalidClaimError::C2paBlockNotFound));
            validation_log.log(
                log_item,
                Some(Error::InvalidClaim(InvalidClaimError::C2paBlockNotFound)),
            )?;

            return Err(Error::InvalidClaim(InvalidClaimError::C2paBlockNotFound));
        }

        let num_stores = cai_block.data_box_count();
        for idx in 0..num_stores {
            let cai_store_box = cai_block
                .data_box_as_superbox(idx)
                .ok_or(Error::JumbfBoxNotFound)?;
            let cai_store_desc_box = cai_store_box.desc_box();

            // ignore unknown boxes per the spec
            if cai_store_desc_box.uuid() != CAI_UPDATE_MANIFEST_UUID
                && cai_store_desc_box.uuid() != CAI_STORE_UUID
            {
                continue;
            }

            // remember the order of the boxes to insure the box hashes can be regenerated
            let mut box_order: Vec<&str> = Vec::new();

            // make sure there are not multiple claim boxes
            let mut claim_box_cnt = 0;
            for i in 0..cai_store_box.data_box_count() {
                let sbox = cai_store_box
                    .data_box_as_superbox(i)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let desc_box = sbox.desc_box();

                if desc_box.uuid() == CAI_CLAIM_UUID {
                    claim_box_cnt += 1;
                }

                if claim_box_cnt > 1 {
                    let log_item =
                        log_item!("JUMBF", "c2pa multiple claim boxes found", "from_jumbf")
                            .error(Error::InvalidClaim(
                                InvalidClaimError::C2paMultipleClaimBoxes,
                            ))
                            .validation_status(validation_status::CLAIM_MULTIPLE);
                    validation_log.log(
                        log_item,
                        Some(Error::InvalidClaim(
                            InvalidClaimError::C2paMultipleClaimBoxes,
                        )),
                    )?;

                    return Err(Error::InvalidClaim(
                        InvalidClaimError::C2paMultipleClaimBoxes,
                    ));
                }

                match desc_box.label().as_ref() {
                    ASSERTIONS => box_order.push(ASSERTIONS),
                    CLAIM => box_order.push(CLAIM),
                    SIGNATURE => box_order.push(SIGNATURE),
                    CREDENTIALS => box_order.push(CREDENTIALS),
                    DATABOXES => box_order.push(DATABOXES),
                    _ => {
                        let log_item =
                            log_item!("JUMBF", "unrecognized manifest box", "from_jumbf")
                                .error(Error::InvalidClaim(InvalidClaimError::ClaimBoxData))
                                .validation_status(validation_status::CLAIM_MULTIPLE);
                        validation_log.log(
                            log_item,
                            Some(Error::InvalidClaim(InvalidClaimError::ClaimBoxData)),
                        )?;
                    }
                }
            }

            let is_update_manifest = cai_store_desc_box.uuid() == CAI_UPDATE_MANIFEST_UUID;

            // get map of boxes in this manifest
            let manifest_boxes = Store::manifest_map(cai_store_box)?;

            // retrieve the claim & validate
            let claim_superbox = manifest_boxes
                .get(CAI_CLAIM_UUID)
                .ok_or(Error::InvalidClaim(
                    InvalidClaimError::ClaimSuperboxNotFound,
                ))?
                .sbox;
            let claim_desc_box = manifest_boxes
                .get(CAI_CLAIM_UUID)
                .ok_or(Error::InvalidClaim(
                    InvalidClaimError::ClaimDescriptionBoxNotFound,
                ))?
                .desc_box;

            // check if version is supported
            let claim_box_ver = claim_desc_box.label();
            if !Self::check_label_version(Claim::build_version(), &claim_box_ver) {
                return Err(Error::InvalidClaim(InvalidClaimError::ClaimVersionTooNew));
            }

            // check box contents
            if claim_desc_box.uuid() == CAI_CLAIM_UUID {
                // must be have only one claim
                if claim_superbox.data_box_count() > 1 {
                    return Err(Error::InvalidClaim(InvalidClaimError::DuplicateClaimBox {
                        label: claim_desc_box.label(),
                    }));
                }
                // better be, but just in case...

                let cbor_box = match claim_superbox.data_box_as_cbor_box(0) {
                    Some(c) => c,
                    None => {
                        // check for old claims for reporting
                        match claim_superbox.data_box_as_json_box(0) {
                            Some(_c) => {
                                let log_item =
                                    log_item!("JUMBF", "error loading claim data", "from_jumbf")
                                        .error(Error::PrereleaseError);
                                validation_log.log_silent(log_item);

                                return Err(Error::PrereleaseError);
                            }
                            None => {
                                let log_item =
                                    log_item!("JUMBF", "error loading claim data", "from_jumbf")
                                        .error(Error::InvalidClaim(
                                            InvalidClaimError::ClaimBoxData,
                                        ));
                                validation_log.log_silent(log_item);
                                return Err(Error::InvalidClaim(InvalidClaimError::ClaimBoxData));
                            }
                        }
                    }
                };

                if cbor_box.box_uuid() != JUMBF_CBOR_UUID {
                    return Err(Error::InvalidClaim(
                        InvalidClaimError::ClaimDescriptionBoxInvalid,
                    ));
                }
            }

            // retrieve the signature
            let sig_superbox = manifest_boxes
                .get(CAI_SIGNATURE_UUID)
                .ok_or(Error::InvalidClaim(
                    InvalidClaimError::ClaimSignatureBoxNotFound,
                ))?
                .sbox;
            let sig_desc_box = manifest_boxes
                .get(CAI_SIGNATURE_UUID)
                .ok_or(Error::InvalidClaim(
                    InvalidClaimError::ClaimSignatureDescriptionBoxNotFound,
                ))?
                .desc_box;

            // check box contents
            if sig_desc_box.uuid() == CAI_SIGNATURE_UUID {
                // better be, but just in case...
                let sig_box = sig_superbox
                    .data_box_as_cbor_box(0)
                    .ok_or(Error::JumbfBoxNotFound)?;
                if sig_box.box_uuid() != JUMBF_CBOR_UUID {
                    return Err(Error::InvalidClaim(
                        InvalidClaimError::ClaimSignatureDescriptionBoxInvalid,
                    ));
                }
            }
            // save signature to be validated on load
            let sig_data = sig_superbox
                .data_box_as_cbor_box(0)
                .ok_or(Error::JumbfBoxNotFound)?;

            // Create a new Claim object from jumbf data after validations
            let cbor_box = claim_superbox
                .data_box_as_cbor_box(0)
                .ok_or(Error::JumbfBoxNotFound)?;
            let mut claim = Claim::from_data(&cai_store_desc_box.label(), cbor_box.cbor())?;

            // set the  type of manifest
            claim.set_update_manifest(is_update_manifest);

            // set order to process JUMBF boxes
            claim.set_box_order(box_order);

            // retrieve & set signature for each claim
            claim.set_signature_val(sig_data.cbor().clone()); // load the stored signature

            // retrieve the assertion store
            let assertion_store_box = manifest_boxes
                .get(CAI_ASSERTION_STORE_UUID)
                .ok_or(Error::InvalidClaim(
                    InvalidClaimError::AssertionStoreSuperboxNotFound,
                ))?
                .sbox;

            let num_assertions = assertion_store_box.data_box_count();

            // loop over all assertions...
            let mut check_for_legacy_assertion = true;
            for idx in 0..num_assertions {
                let assertion_box = assertion_store_box
                    .data_box_as_superbox(idx)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let assertion_desc_box = assertion_box.desc_box();

                // Add assertions to claim after validation
                let label = assertion_desc_box.label();
                match Store::get_assertion_from_jumbf_store(
                    &claim,
                    assertion_box,
                    &label,
                    check_for_legacy_assertion,
                ) {
                    Ok(assertion) => {
                        claim.put_assertion_store(assertion); // restore assertion data to claim
                        check_for_legacy_assertion = false; // only need to
                                                            // check once
                    }
                    Err(e) => {
                        // if this is an old manifest always return
                        if std::mem::discriminant(&e)
                            == std::mem::discriminant(&Error::PrereleaseError)
                        {
                            let log_item =
                                log_item!("JUMBF", "error loading assertion", "from_jumbf")
                                    .error(e);
                            validation_log.log_silent(log_item);
                            return Err(Error::PrereleaseError);
                        } else {
                            let log_item =
                                log_item!("JUMBF", "error loading assertion", "from_jumbf")
                                    .error(e);
                            validation_log.log(log_item, None)?;
                        }
                    }
                }
            }

            // load vc_store if available
            if let Some(mi) = manifest_boxes.get(CAI_VERIFIABLE_CREDENTIALS_STORE_UUID) {
                let vc_store = mi.sbox;
                let num_vcs = vc_store.data_box_count();

                for idx in 0..num_vcs {
                    let vc_box = vc_store
                        .data_box_as_superbox(idx)
                        .ok_or(Error::JumbfBoxNotFound)?;
                    let vc_json = vc_box
                        .data_box_as_json_box(0)
                        .ok_or(Error::JumbfBoxNotFound)?;
                    let vc_desc_box = vc_box.desc_box();
                    let _id = vc_desc_box.label();

                    let json_str = String::from_utf8(vc_json.json().to_vec())
                        .map_err(|_| InvalidClaimError::VerifiableCredentialStoreInvalid)?;

                    let salt = vc_desc_box.get_salt();

                    claim.put_verifiable_credential(&json_str, salt)?;
                }
            }

            // load databox store if available
            if let Some(mi) = manifest_boxes.get(CAI_DATABOXES_STORE_UUID) {
                let databox_store = mi.sbox;
                let num_databoxes = databox_store.data_box_count();

                for idx in 0..num_databoxes {
                    let db_box = databox_store
                        .data_box_as_superbox(idx)
                        .ok_or(Error::JumbfBoxNotFound)?;
                    let db_cbor = db_box
                        .data_box_as_cbor_box(0)
                        .ok_or(Error::JumbfBoxNotFound)?;
                    let db_desc_box = db_box.desc_box();
                    let label = db_desc_box.label();

                    let salt = db_desc_box.get_salt();

                    claim.put_data_box(&label, db_cbor.cbor(), salt)?;
                }
            }

            // save the hash of the loaded manifest for ingredient validation
            store.manifest_box_hash_cache.insert(
                claim.label().to_owned(),
                Store::calc_manifest_box_hash(&claim, None, claim.alg())?,
            );

            // add claim to store
            store.insert_restored_claim(cai_store_desc_box.label(), claim);
        }

        Ok(store)
    }

    // Get the store label from jumbf path
    pub fn manifest_label_from_path(claim_path: &str) -> String {
        if let Some(s) = jumbf::labels::manifest_label_from_uri(claim_path) {
            s
        } else {
            claim_path.to_owned()
        }
    }

    // wake the ingredients and validate
    fn ingredient_checks(
        _store: &Store,
        _claim: &Claim,
        _asset_data: &mut ClaimAssetData<'_>,
        _validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        Ok(())
    }

    // wake the ingredients and validate
    async fn ingredient_checks_async(
        _store: &Store,
        _claim: &Claim,
        _asset_data: &mut ClaimAssetData<'_>,
        _validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        Ok(())
    }

    /// Verify Store
    /// store: Store to validate
    /// xmp_str: String containing entire XMP block of the asset
    /// asset_bytes: bytes of the asset to be verified
    /// validation_log: If present all found errors are logged and returned,
    /// other wise first error causes exit and is returned
    pub async fn verify_store_async(
        store: &Store,
        asset_data: &mut ClaimAssetData<'_>,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        let claim = match store.provenance_claim() {
            Some(c) => c,
            None => {
                let log_item =
                    log_item!("Unknown", "could not find active manifest", "verify_store")
                        .error(Error::ProvenanceMissing)
                        .validation_status(validation_status::CLAIM_MISSING);
                validation_log.log(log_item, Some(Error::ProvenanceMissing))?;

                return Err(Error::ProvenanceMissing);
            }
        };

        // verify the provenance claim
        Claim::verify_claim_async(
            claim,
            asset_data,
            true,
            store.trust_handler(),
            validation_log,
        )
        .await?;

        Store::ingredient_checks_async(store, claim, asset_data, validation_log).await?;

        Ok(())
    }

    /// Verify Store
    /// store: Store to validate
    /// xmp_str: String containing entire XMP block of the asset
    /// asset_bytes: bytes of the asset to be verified
    /// validation_log: If present all found errors are logged and returned,
    /// other wise first error causes exit and is returned
    pub fn verify_store(
        store: &Store,
        asset_data: &mut ClaimAssetData<'_>,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        let claim = match store.provenance_claim() {
            Some(c) => c,
            None => {
                let log_item =
                    log_item!("Unknown", "could not find active manifest", "verify_store")
                        .error(Error::ProvenanceMissing)
                        .validation_status(validation_status::CLAIM_MISSING);
                validation_log.log(log_item, Some(Error::ProvenanceMissing))?;

                return Err(Error::ProvenanceMissing);
            }
        };

        // verify the provenance claim
        Claim::verify_claim(
            claim,
            asset_data,
            true,
            store.trust_handler(),
            validation_log,
        )?;

        Store::ingredient_checks(store, claim, asset_data, validation_log)?;

        Ok(())
    }

    // generate a list of AssetHashes based on the location of objects in the stream
    fn generate_data_hashes_for_stream<R>(
        stream: &mut R,
        alg: &str,
        block_locations: &mut Vec<HashObjectPositions>,
        calc_hashes: bool,
    ) -> Result<Vec<DataHash>>
    where
        R: Read + Seek + ?Sized,
    {
        if block_locations.is_empty() {
            let out: Vec<DataHash> = vec![];
            return Ok(out);
        }

        let stream_len = stream.seek(SeekFrom::End(0))?;
        stream.rewind()?;

        let mut hashes: Vec<DataHash> = Vec::new();

        // sort blocks by offset
        block_locations.sort_by(|a, b| a.offset.cmp(&b.offset));

        // generate default data hash that excludes jumbf block
        // find the first jumbf block (ours are always in order)
        // find the first block after the jumbf blocks
        let mut block_start: usize = 0;
        let mut block_end: usize = 0;
        let mut found_jumbf = false;
        for item in block_locations {
            // find start of jumbf
            if !found_jumbf && item.htype == HashBlockObjectType::Cai {
                block_start = item.offset;
                found_jumbf = true;
            }

            // find start of block after jumbf blocks
            if found_jumbf && item.htype == HashBlockObjectType::Cai {
                block_end = item.offset + item.length;
            }
        }

        if found_jumbf {
            // add exclusion hash for bytes before and after jumbf
            let mut dh = DataHash::new("jumbf manifest", alg);
            if block_end > block_start {
                dh.add_exclusion(HashRange::new(block_start, block_end - block_start));
            }

            if calc_hashes {
                // this check is only valid on the final sized asset
                if block_end as u64 > stream_len {
                    return Err(Error::BadParam(
                        "data hash exclusions out of range".to_string(),
                    ));
                }

                dh.gen_hash_from_stream(stream)?;
            } else {
                match alg {
                    "sha256" => dh.set_hash([0u8; 32].to_vec()),
                    "sha384" => dh.set_hash([0u8; 48].to_vec()),
                    "sha512" => dh.set_hash([0u8; 64].to_vec()),
                    _ => return Err(Error::UnsupportedType),
                }
            }
            hashes.push(dh);
        }

        Ok(hashes)
    }

    /// This function is used to pre-generate a manifest with place holders for
    /// the final DataHash and Manifest Signature.  The DataHash will
    /// reserve space for at least 10 Exclusion ranges.  The Signature box
    /// reserved size is based on the size required by the Signer you plan
    /// to use.  This function is not needed when using Box Hash. This function
    /// is used in conjunction with `get_data_hashed_embeddable_manifest`.
    /// The manifest returned from `get_data_hashed_embeddable_manifest`
    /// will have a size that matches this function.
    pub fn get_data_hashed_manifest_placeholder(
        &mut self,
        reserve_size: usize,
        format: &str,
    ) -> Result<Vec<u8>> {
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

        // if user did not supply a hash
        if pc.hash_assertions().is_empty() {
            // create placeholder DataHash large enough for 10 Exclusions
            let mut ph = DataHash::new("jumbf manifest", pc.alg());
            for _ in 0..10 {
                ph.add_exclusion(HashRange::new(0, 2));
            }
            let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            let mut stream = Cursor::new(data);
            ph.gen_hash_from_stream(&mut stream)?;

            pc.add_assertion_with_salt(&ph, &DefaultSalt::default())?;
        }

        let jumbf_bytes = self.to_jumbf_internal(reserve_size)?;

        let composed = Self::get_composed_manifest(&jumbf_bytes, format)?;

        Ok(composed)
    }

    fn prep_embeddable_store(
        &mut self,
        reserve_size: usize,
        dh: &DataHash,
        asset_reader: Option<&mut dyn CAIRead>,
    ) -> Result<Vec<u8>> {
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

        // make sure there are data hashes present before generating
        if pc.hash_assertions().is_empty() {
            return Err(Error::BadParam(
                "Claim must have hash binding assertion".to_string(),
            ));
        }

        let mut adjusted_dh = DataHash::new("jumbf manifest", pc.alg());
        adjusted_dh.exclusions.clone_from(&dh.exclusions);
        adjusted_dh.hash.clone_from(&dh.hash);

        if let Some(reader) = asset_reader {
            // calc hashes
            adjusted_dh.gen_hash_from_stream(reader)?;
        }

        // update the placeholder hash
        pc.update_data_hash(adjusted_dh)?;

        self.to_jumbf_internal(reserve_size)
    }

    fn finish_embeddable_store(
        &mut self,
        sig: &[u8],
        sig_placeholder: &[u8],
        jumbf_bytes: &mut Vec<u8>,
        format: &str,
    ) -> Result<Vec<u8>> {
        if sig_placeholder.len() != sig.len() {
            return Err(Error::CoseSigboxTooSmall);
        }

        patch_bytes(jumbf_bytes, sig_placeholder, sig).map_err(|_| Error::JumbfCreationError)?;

        Self::get_composed_manifest(jumbf_bytes, format)
    }

    /// Returns a finalized, signed manifest.  The manifest are only supported
    /// for cases when the client has provided a data hash content hash binding.
    /// Note, this function will not work for cases like BMFF where the
    /// position of the content is also encoded.  This function is not
    /// compatible with BMFF hash binding.  If a BMFF data hash or box hash
    /// is detected that is an error.  The DataHash placeholder assertion
    /// will be  adjusted to the contain the correct values.  If the
    /// asset_reader value is supplied it will also perform
    /// the hash calculations, otherwise the function uses the caller supplied
    /// values. It is an error if `get_data_hashed_manifest_placeholder` was
    /// not called first as this call inserts the DataHash placeholder
    /// assertion to reserve space for the actual hash values not required
    /// when using BoxHashes.
    pub fn get_data_hashed_embeddable_manifest(
        &mut self,
        dh: &DataHash,
        signer: &dyn Signer,
        format: &str,
        asset_reader: Option<&mut dyn CAIRead>,
    ) -> Result<Vec<u8>> {
        let mut jumbf_bytes =
            self.prep_embeddable_store(signer.reserve_size(), dh, asset_reader)?;

        // sign contents
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = self.sign_claim(pc, signer, signer.reserve_size())?;

        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        self.finish_embeddable_store(&sig, &sig_placeholder, &mut jumbf_bytes, format)
    }

    /// Returns a finalized, signed manifest.  The manifest are only supported
    /// for cases when the client has provided a data hash content hash binding.
    /// Note, this function will not work for cases like BMFF where the
    /// position of the content is also encoded.  This function is not
    /// compatible with BMFF hash binding.  If a BMFF data hash or box hash
    /// is detected that is an error.  The DataHash placeholder assertion
    /// will be  adjusted to the contain the correct values.  If the
    /// asset_reader value is supplied it will also perform
    /// the hash calculations, otherwise the function uses the caller supplied
    /// values. It is an error if `get_data_hashed_manifest_placeholder` was
    /// not called first as this call inserts the DataHash placeholder
    /// assertion to reserve space for the actual hash values not required
    /// when using BoxHashes.
    pub async fn get_data_hashed_embeddable_manifest_async(
        &mut self,
        dh: &DataHash,
        signer: &dyn AsyncSigner,
        format: &str,
        asset_reader: Option<&mut dyn CAIRead>,
    ) -> Result<Vec<u8>> {
        let mut jumbf_bytes =
            self.prep_embeddable_store(signer.reserve_size(), dh, asset_reader)?;

        // sign contents
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = self
            .sign_claim_async(pc, signer, signer.reserve_size())
            .await?;

        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        self.finish_embeddable_store(&sig, &sig_placeholder, &mut jumbf_bytes, format)
    }

    /// Returns a finalized, signed manifest.  The manifest are only supported
    /// for cases when the client has provided a data hash content hash binding.
    /// Note, this function will not work for cases like BMFF where the
    /// position of the content is also encoded.  This function is not
    /// compatible with BMFF hash binding.  If a BMFF data hash or box hash
    /// is detected that is an error.  The DataHash placeholder assertion
    /// will be  adjusted to the contain the correct values.  If the
    /// asset_reader value is supplied it will also perform
    /// the hash calculations, otherwise the function uses the caller supplied
    /// values. It is an error if `get_data_hashed_manifest_placeholder` was
    /// not called first as this call inserts the DataHash placeholder
    /// assertion to reserve space for the actual hash values not required
    /// when using BoxHashes.
    pub async fn get_data_hashed_embeddable_manifest_remote(
        &mut self,
        dh: &DataHash,
        signer: &dyn RemoteSigner,
        format: &str,
        asset_reader: Option<&mut dyn CAIRead>,
    ) -> Result<Vec<u8>> {
        let mut jumbf_bytes =
            self.prep_embeddable_store(signer.reserve_size(), dh, asset_reader)?;

        // sign contents
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let claim_bytes = pc.data()?;
        let sig = signer.sign_remote(&claim_bytes).await?;

        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        self.finish_embeddable_store(&sig, &sig_placeholder, &mut jumbf_bytes, format)
    }

    /// Returns a finalized, signed manifest.  The client is required to have
    /// included the necessary box hash assertion with the pregenerated hashes.
    pub fn get_box_hashed_embeddable_manifest(&mut self, signer: &dyn Signer) -> Result<Vec<u8>> {
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;

        // make sure there is only one
        if pc.hash_assertions().len() != 1 {
            return Err(Error::BadParam(
                "Claim must have exactly one hash binding assertion".to_string(),
            ));
        }

        // only allow box hash assertions to be present
        if pc.box_hash_assertions().is_empty() {
            return Err(Error::BadParam("Missing box hash assertion".to_string()));
        }

        let mut jumbf_bytes = self.to_jumbf_internal(signer.reserve_size())?;

        // sign contents
        let sig = self.sign_claim(pc, signer, signer.reserve_size())?;
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        if sig_placeholder.len() != sig.len() {
            return Err(Error::CoseSigboxTooSmall);
        }

        patch_bytes(&mut jumbf_bytes, &sig_placeholder, &sig)
            .map_err(|_| Error::JumbfCreationError)?;

        Ok(jumbf_bytes)
    }

    /// Returns a finalized, signed manifest.  The client is required to have
    /// included the necessary box hash assertion with the pregenerated hashes.
    pub async fn get_box_hashed_embeddable_manifest_async(
        &mut self,
        signer: &dyn AsyncSigner,
    ) -> Result<Vec<u8>> {
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;

        // make sure there is only one
        if pc.hash_assertions().len() != 1 {
            return Err(Error::BadParam(
                "Claim must have exactly one hash binding assertion".to_string(),
            ));
        }

        // only allow box hash assertions to be present
        if pc.box_hash_assertions().is_empty() {
            return Err(Error::BadParam("Missing box hash assertion".to_string()));
        }

        let mut jumbf_bytes = self.to_jumbf_internal(signer.reserve_size())?;

        // sign contents
        let sig = self
            .sign_claim_async(pc, signer, signer.reserve_size())
            .await?;
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        if sig_placeholder.len() != sig.len() {
            return Err(Error::CoseSigboxTooSmall);
        }

        patch_bytes(&mut jumbf_bytes, &sig_placeholder, &sig)
            .map_err(|_| Error::JumbfCreationError)?;

        Ok(jumbf_bytes)
    }

    /// Returns the supplied manifest composed to be directly compatible with
    /// the desired format. For example, if format is JPEG function will
    /// return the set of APP11 segments that contains the manifest.
    pub fn get_composed_manifest(manifest_bytes: &[u8], format: &str) -> Result<Vec<u8>> {
        if let Some(h) = get_assetio_handler(format) {
            if let Some(composed_data_handler) = h.composed_data_ref() {
                return composed_data_handler.compose_manifest(manifest_bytes, format);
            }
        }
        Err(Error::UnsupportedType)
    }

    /// Embed the claims store as jumbf into a stream. Updates XMP with
    /// provenance record. When called, the stream should contain an asset
    /// matching format. on return, the stream will contain the new manifest
    /// signed with signer This directly modifies the asset in stream,
    /// backup stream first if you need to preserve it. This can also handle
    /// remote signing if direct_cose_handling() is true.
    #[async_generic(async_signature(
        &mut self,
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        signer: &dyn AsyncSigner,
    ))]
    pub fn save_to_stream(
        &mut self,
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        let intermediate_output: Vec<u8> = Vec::new();
        let mut intermediate_stream = Cursor::new(intermediate_output);

        let jumbf_bytes = self.start_save_stream(
            format,
            input_stream,
            &mut intermediate_stream,
            signer.reserve_size(),
        )?;

        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = if _sync {
            self.sign_claim(pc, signer, signer.reserve_size())
        } else {
            self.sign_claim_async(pc, signer, signer.reserve_size())
                .await
        }?;
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        intermediate_stream.rewind()?;
        match self.finish_save_stream(
            jumbf_bytes,
            format,
            &mut intermediate_stream,
            output_stream,
            sig,
            &sig_placeholder,
        ) {
            Ok((s, m)) => {
                // save sig so store is up to date
                let pc_mut = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
                pc_mut.set_signature_val(s);

                Ok(m)
            }
            Err(e) => Err(e),
        }
    }

    /// This function is used to pre-generate a manifest as if it were added to
    /// input_stream. All values are complete including the hash bindings,
    /// except for the signature.  The signature is completed during
    /// the actual embedding using `embed_placed_manifest `.   The Signature box
    /// reserve_size is based on the size required by the Signer you plan to
    /// use.  This function is not needed when using Box Hash. This function is
    /// used in conjunction with `embed_placed_manifest`.
    /// `embed_placed_manifest` will accept the manifest to sign and place
    /// in the output.
    pub fn get_placed_manifest(
        &mut self,
        reserve_size: usize,
        format: &str,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<u8>> {
        let intermediate_output: Vec<u8> = Vec::new();
        let mut intermediate_stream = Cursor::new(intermediate_output);

        self.start_save_stream(format, input_stream, &mut intermediate_stream, reserve_size)
    }

    /// Embed the manifest store into an asset. If a ManifestPatchCallback is
    /// present the caller is given an opportunity to adjust most
    /// assertions.  This function will not generate hash binding for the
    /// manifest.  It is assumed the user called
    /// get_box_hashed_embeddable_manifest hash or provided a box hash
    /// binding.  The input stream should reference the same content used in
    /// the 'get_placed_manifest_call'.  Changes to the following assertions are
    /// disallowed when using 'ManifestPatchCallback':  ["c2pa.hash.data",
    /// "c2pa.hash.boxes",  "c2pa.hash.bmff",  "c2pa.actions",
    /// "c2pa.ingredient"].  Also the set of assertions cannot be changed, only
    /// the content of allowed assertions can be modified.  
    /// 'format' shoould match the type of the input stream..
    /// Upon return, the output stream will contain the new manifest signed with
    /// signer This directly modifies the asset in stream, backup stream
    /// first if you need to preserve it.

    #[async_generic(
        async_signature(
            manifest_bytes: &[u8],
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        signer: &dyn AsyncSigner,
        manifest_callbacks: &[Box<dyn ManifestPatchCallback>],
        ))]
    pub fn embed_placed_manifest(
        manifest_bytes: &[u8],
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        signer: &dyn Signer,
        manifest_callbacks: &[Box<dyn ManifestPatchCallback>],
    ) -> Result<Vec<u8>> {
        // todo: Consider how we would add XMP for this case

        let disallowed_assertions = [
            labels::DATA_HASH,
            labels::BOX_HASH,
            labels::ACTIONS,
            labels::INGREDIENT,
        ];

        let mut validation_log = DetailedStatusTracker::new();
        let mut store = Store::from_jumbf(manifest_bytes, &mut validation_log)?;

        // todo: what kinds of validation can we do here since the file is not
        // finailized;

        let pc_mut = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

        // save the current assertions set so that we can check them after callback;
        let claim_assertions = pc_mut.claim_assertion_store().clone();

        let manifest_bytes_updated = if !manifest_callbacks.is_empty() {
            let mut updated = manifest_bytes.to_vec();

            // callback to all patch functions
            for mpc in manifest_callbacks {
                updated = mpc.patch_manifest(&updated)?;
            }

            // make sure the size is correct
            if updated.len() != manifest_bytes.len() {
                return Err(Error::OtherError("patched manifest size incorrect".into()));
            }

            // make sure we can load the patched manifest
            let new_store = Store::from_jumbf(&updated, &mut validation_log)?;

            let new_pc = new_store.provenance_claim().ok_or(Error::ClaimEncoding)?;

            // make sure the claim has not changed
            if !vec_compare(&pc_mut.data()?, &new_pc.data()?) {
                return Err(Error::OtherError(
                    "patched manifest changed the Claim structure".into(),
                ));
            }

            // check to make sure assertion changes are OK and nothing else changed.
            if claim_assertions.len() != new_pc.claim_assertion_store().len() {
                return Err(Error::OtherError(
                    "patched manifest assertion list has changed".into(),
                ));
            }

            // get the list of assertions that need patching
            for ca in claim_assertions {
                if let Some(updated_ca) = new_pc.get_claim_assertion(&ca.label_raw(), ca.instance())
                {
                    // if hashes are different then this assertion has changed so attempt fixup
                    if !vec_compare(ca.hash(), updated_ca.hash()) {
                        if disallowed_assertions
                            .iter()
                            .any(|&l| l == updated_ca.label_raw())
                        {
                            return Err(Error::OtherError(
                                "patched manifest changed a disallowed assertion".into(),
                            ));
                        }

                        // update original
                        pc_mut.update_assertion(
                            updated_ca.assertion().clone(),
                            |_: &ClaimAssertion| true,
                            |target_assertion: &ClaimAssertion, a: Assertion| {
                                if target_assertion.assertion().data().len() == a.data().len() {
                                    Ok(a)
                                } else {
                                    Err(Error::OtherError(
                                        "patched manifest assertion size differ in size".into(),
                                    ))
                                }
                            },
                        )?;
                    }
                } else {
                    return Err(Error::OtherError(
                        "patched manifest assertion list has changed".into(),
                    ));
                }
            }

            store.to_jumbf_internal(signer.reserve_size())?
        } else {
            manifest_bytes.to_vec()
        };

        // sign the updated manfiest
        let pc = store.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = if _sync {
            store.sign_claim(pc, signer, signer.reserve_size())?
        } else {
            store
                .sign_claim_async(pc, signer, signer.reserve_size())
                .await?
        };
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        match store.finish_save_stream(
            manifest_bytes_updated,
            format,
            input_stream,
            output_stream,
            sig,
            &sig_placeholder,
        ) {
            Ok((_, m)) => Ok(m),
            Err(e) => Err(e),
        }
    }

    fn start_save_stream(
        &mut self,
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        reserve_size: usize,
    ) -> Result<Vec<u8>> {
        let intermediate_output: Vec<u8> = Vec::new();
        let mut intermediate_stream = Cursor::new(intermediate_output);

        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

        // Add remote reference XMP if needed and strip out existing manifest
        // We don't need to strip manifests if we are replacing an exsiting one
        let (url, remove_manifests) = match pc.remote_manifest() {
            RemoteManifest::NoRemote => (None, false),
            RemoteManifest::SideCar => (None, true),
            RemoteManifest::Remote(url) => (Some(url), true),
            RemoteManifest::EmbedWithRemote(url) => (Some(url), false),
        };

        let io_handler = get_assetio_handler(format).ok_or(Error::UnsupportedType)?;

        // Do not assume the handler supports XMP or removing manifests unless we need
        // it to
        if let Some(url) = url {
            let external_ref_writer = io_handler
                .remote_ref_writer_ref()
                .ok_or(Error::XmpNotSupported)?;

            if remove_manifests {
                let manifest_writer = io_handler
                    .get_writer(format)
                    .ok_or(Error::UnsupportedType)?;

                let tmp_output: Vec<u8> = Vec::new();
                let mut tmp_stream = Cursor::new(tmp_output);
                manifest_writer.remove_cai_store_from_stream(input_stream, &mut tmp_stream)?;

                // add external ref if possible
                tmp_stream.rewind()?;
                external_ref_writer.embed_reference_to_stream(
                    &mut tmp_stream,
                    &mut intermediate_stream,
                    RemoteRefEmbedType::Xmp(url),
                )?;
            } else {
                // add external ref if possible
                external_ref_writer.embed_reference_to_stream(
                    input_stream,
                    &mut intermediate_stream,
                    RemoteRefEmbedType::Xmp(url),
                )?;
            }
        } else if remove_manifests {
            let manifest_writer = io_handler
                .get_writer(format)
                .ok_or(Error::UnsupportedType)?;

            manifest_writer.remove_cai_store_from_stream(input_stream, &mut intermediate_stream)?;
        } else {
            // just clone stream
            input_stream.rewind()?;
            std::io::copy(input_stream, &mut intermediate_stream)?;
        }

        let mut data;

        // we will not do automatic hashing if we detect a box hash present
        let mut needs_hashing = false;
        if pc.hash_assertions().is_empty() {
            // 2) Get hash ranges if needed, do not generate for update manifests
            let mut hash_ranges = object_locations_from_stream(format, &mut intermediate_stream)?;
            let hashes: Vec<DataHash> = if pc.update_manifest() {
                Vec::new()
            } else {
                Store::generate_data_hashes_for_stream(
                    &mut intermediate_stream,
                    pc.alg(),
                    &mut hash_ranges,
                    false,
                )?
            };

            // add the placeholder data hashes to provenance claim so that the required
            // space is reserved
            for mut hash in hashes {
                // add padding to account for possible cbor expansion of final DataHash
                let padding: Vec<u8> = vec![0x0; 10];
                hash.add_padding(padding);

                pc.add_assertion(&hash)?;
            }
            needs_hashing = true;
        }

        // 3) Generate in memory CAI jumbf block
        data = self.to_jumbf_internal(reserve_size)?;
        let jumbf_size = data.len();

        // write the jumbf to the output stream if we are embedding the manifest
        if !remove_manifests {
            intermediate_stream.rewind()?;
            save_jumbf_to_stream(format, &mut intermediate_stream, output_stream, &data)?;
        } else {
            // just copy the asset to the output stream without an embedded manifest (may be
            // stripping one out here)
            intermediate_stream.rewind()?;
            std::io::copy(&mut intermediate_stream, output_stream)?;
        }

        // 4) determine final object locations and patch the asset hashes with correct
        //    offset
        // replace the source with correct asset hashes so that the claim hash will be
        // correct
        if needs_hashing {
            let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

            // get the final hash ranges, but not for update manifests
            output_stream.rewind()?;
            let mut new_hash_ranges = object_locations_from_stream(format, output_stream)?;
            if !pc.update_manifest() {
                let updated_hashes = Store::generate_data_hashes_for_stream(
                    output_stream,
                    pc.alg(),
                    &mut new_hash_ranges,
                    true,
                )?;

                // patch existing claim hash with updated data
                for hash in updated_hashes {
                    pc.update_data_hash(hash)?;
                }
            }
        }

        // regenerate the jumbf because the cbor changed
        data = self.to_jumbf_internal(reserve_size)?;
        if jumbf_size != data.len() {
            return Err(Error::JumbfCreationError);
        }

        Ok(data) // return JUMBF data
    }

    fn finish_save_stream(
        &self,
        mut jumbf_bytes: Vec<u8>,
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        sig: Vec<u8>,
        sig_placeholder: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if sig_placeholder.len() != sig.len() {
            return Err(Error::CoseSigboxTooSmall);
        }

        patch_bytes(&mut jumbf_bytes, sig_placeholder, &sig)
            .map_err(|_| Error::JumbfCreationError)?;

        // re-save to file
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        match pc.remote_manifest() {
            RemoteManifest::NoRemote | RemoteManifest::EmbedWithRemote(_) => {
                save_jumbf_to_stream(format, input_stream, output_stream, &jumbf_bytes)?;
            }
            RemoteManifest::SideCar | RemoteManifest::Remote(_) => {
                // just copy the asset to the output stream without an embedded manifest (may be
                // stripping one out here)
                std::io::copy(input_stream, output_stream)?;
            }
        }

        Ok((sig, jumbf_bytes))
    }

    // verify from a buffer without file i/o
    pub fn verify_from_buffer(
        &mut self,
        buf: &[u8],
        asset_type: &str,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        Store::verify_store(
            self,
            &mut ClaimAssetData::Bytes(buf, asset_type),
            validation_log,
        )
    }

    // verify from a buffer without file i/o
    pub fn verify_from_stream(
        &mut self,
        reader: &mut dyn CAIRead,
        asset_type: &str,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        Store::verify_store(
            self,
            &mut ClaimAssetData::Stream(reader, asset_type),
            validation_log,
        )
    }

    fn handle_remote_manifest(ext_ref: &str) -> Result<Vec<u8>> {
        // verify provenance path is remote url
        if Store::is_valid_remote_url(ext_ref) {
            Err(Error::RemoteManifestUrl(ext_ref.to_owned()))
        } else {
            Err(Error::JumbfNotFound)
        }
    }

    /// Return Store from in memory asset
    fn load_cai_from_memory(
        asset_type: &str,
        data: &[u8],
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        let mut input_stream = Cursor::new(data);
        Store::load_jumbf_from_stream(asset_type, &mut input_stream)
            .map(|manifest_bytes| Store::from_jumbf(&manifest_bytes, validation_log))?
    }

    /// load jumbf given a stream
    ///
    /// This handles, embedded and remote manifests
    ///
    /// asset_type -  mime type of the stream
    /// stream - a readable stream of an asset
    pub fn load_jumbf_from_stream(asset_type: &str, stream: &mut dyn CAIRead) -> Result<Vec<u8>> {
        match load_jumbf_from_stream(asset_type, stream) {
            Ok(manifest_bytes) => Ok(manifest_bytes),
            Err(Error::JumbfNotFound) => {
                stream.rewind()?;
                if let Some(ext_ref) =
                    crate::utils::xmp_inmemory_utils::XmpInfo::from_source(stream, asset_type)
                        .provenance
                {
                    Store::handle_remote_manifest(&ext_ref)
                } else {
                    Err(Error::JumbfNotFound)
                }
            }
            Err(e) => Err(e),
        }
    }

    pub fn get_store_from_memory(
        asset_type: &str,
        data: &[u8],
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        // load jumbf if available
        Self::load_cai_from_memory(asset_type, data, validation_log).map_err(|e| {
            validation_log.log_silent(
                log_item!("asset", "error loading asset", "get_store_from_memory").set_error(&e),
            );
            e
        })
    }

    /// Returns embedded remote manifest URL if available
    /// asset_type: extensions or mime type of the data
    /// data: byte array containing the asset
    pub fn get_remote_manifest_url(asset_type: &str, data: &[u8]) -> Option<String> {
        let mut buf_reader = Cursor::new(data);

        if let Some(ext_ref) =
            crate::utils::xmp_inmemory_utils::XmpInfo::from_source(&mut buf_reader, asset_type)
                .provenance
        {
            // make sure it parses
            let _u = url::Url::parse(&ext_ref).ok()?;
            Some(ext_ref)
        } else {
            None
        }
    }

    /// check the input url to see if it is a supported remotes URI
    pub fn is_valid_remote_url(url: &str) -> bool {
        match url::Url::parse(url) {
            Ok(u) => u.scheme() == "http" || u.scheme() == "https",
            Err(_) => false,
        }
    }

    /// Load Store from a in-memory asset
    /// asset_type: asset extension or mime type
    /// data: reference to bytes of the the file
    /// verify: if true will run verification checks when loading
    /// validation_log: If present all found errors are logged and returned,
    /// otherwise first error causes exit and is returned
    pub fn load_from_memory(
        asset_type: &str,
        data: &[u8],
        verify: bool,
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        Store::get_store_from_memory(asset_type, data, validation_log).and_then(|store| {
            // verify the store
            if verify {
                // verify store and claims
                Store::verify_store(
                    &store,
                    &mut ClaimAssetData::Bytes(data, asset_type),
                    validation_log,
                )?;
            }

            Ok(store)
        })
    }

    /// Load Store from a in-memory asset asynchronously validating
    /// asset_type: asset extension or mime type
    /// data: reference to bytes of the file
    /// verify: if true will run verification checks when loading
    /// validation_log: If present all found errors are logged and returned,
    /// otherwise first error causes exit and is returned
    pub async fn load_from_memory_async(
        asset_type: &str,
        data: &[u8],
        verify: bool,
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        let store = Store::get_store_from_memory(asset_type, data, validation_log)?;

        // verify the store
        if verify {
            // verify store and claims
            Store::verify_store_async(
                &store,
                &mut ClaimAssetData::Bytes(data, asset_type),
                validation_log,
            )
            .await?;
        }

        Ok(store)
    }

    /// Load Store from a in-memory asset
    /// asset_type: asset extension or mime type
    /// data: reference to bytes of the the file
    /// verify: if true will run verification checks when loading
    /// validation_log: If present all found errors are logged and returned,
    /// otherwise first error causes exit and is returned
    pub fn load_fragment_from_memory(
        asset_type: &str,
        init_segment: &[u8],
        fragment: &[u8],
        verify: bool,
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        Store::get_store_from_memory(asset_type, init_segment, validation_log).and_then(|store| {
            // verify the store
            if verify {
                let mut init_segment_stream = Cursor::new(init_segment);
                let mut fragment_stream = Cursor::new(fragment);

                // verify store and claims
                Store::verify_store(
                    &store,
                    &mut ClaimAssetData::StreamFragment(
                        &mut init_segment_stream,
                        &mut fragment_stream,
                        asset_type,
                    ),
                    validation_log,
                )?;
            }

            Ok(store)
        })
    }

    /// Load Store from a in-memory asset asynchronously validating
    /// asset_type: asset extension or mime type
    /// init_segment: reference to bytes of the init segment
    /// fragment: reference to bytes of the fragment to validate
    /// verify: if true will run verification checks when loading
    /// validation_log: If present all found errors are logged and returned,
    /// otherwise first error causes exit and is returned
    pub async fn load_fragment_from_memory_async(
        asset_type: &str,
        init_segment: &[u8],
        fragment: &[u8],
        verify: bool,
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        let store = Store::get_store_from_memory(asset_type, init_segment, validation_log)?;

        // verify the store
        if verify {
            let mut init_segment_stream = Cursor::new(init_segment);
            let mut fragment_stream = Cursor::new(fragment);

            // verify store and claims
            Store::verify_store_async(
                &store,
                &mut ClaimAssetData::StreamFragment(
                    &mut init_segment_stream,
                    &mut fragment_stream,
                    asset_type,
                ),
                validation_log,
            )
            .await?;
        }

        Ok(store)
    }

    /// Load Store from memory and add its content as a claim ingredient
    /// claim: claim to add an ingredient
    /// provenance_label: label of the provenance claim used as key into
    /// ingredient map data: jumbf data block
    pub fn load_ingredient_to_claim(
        claim: &mut Claim,
        provenance_label: &str,
        data: &[u8],
        redactions: Option<Vec<String>>,
    ) -> Result<Store> {
        let mut report = OneShotStatusTracker::new();
        let store = Store::from_jumbf(data, &mut report)?;
        claim.add_ingredient_data(provenance_label, store.claims.clone(), redactions)?;
        Ok(store)
    }
}

impl std::fmt::Display for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Store::display no longer implemented")
    }
}

/// `InvalidClaimError` provides additional detail on error cases for
/// [`Store::from_jumbf`].
#[derive(Debug, thiserror::Error)]
pub enum InvalidClaimError {
    /// The "c2pa" block was not found in the asset.
    #[error("\"c2pa\" block not found")]
    C2paBlockNotFound,

    #[error("\"c2pa\" multiple claim boxes found in manifest")]
    C2paMultipleClaimBoxes,

    /// The claim superbox was not found.
    #[error("claim superbox not found")]
    ClaimSuperboxNotFound,

    /// The claim description box was not found.
    #[error("claim description box not found")]
    ClaimDescriptionBoxNotFound,

    /// More than one claim description box was found.
    #[error("more than one claim description box was found for {label}")]
    DuplicateClaimBox { label: String },

    /// The expected data not found in claim box.
    #[error("claim cbor box not valid")]
    ClaimBoxData,

    /// The claim has a version that is newer than supported by this crate.
    #[error("claim version is too new, not supported")]
    ClaimVersionTooNew,

    /// The claim description box could not be parsed.
    #[error("claim description box was invalid")]
    ClaimDescriptionBoxInvalid,

    /// The claim signature box was not found.
    #[error("claim signature box was not found")]
    ClaimSignatureBoxNotFound,

    /// The claim signature description box was not found.
    #[error("claim signature description box was not found")]
    ClaimSignatureDescriptionBoxNotFound,

    /// The claim signature description box was invalid.
    #[error("claim signature description box was invalid")]
    ClaimSignatureDescriptionBoxInvalid,

    /// The assertion store superbox was not found.
    #[error("assertion store superbox not found")]
    AssertionStoreSuperboxNotFound,

    /// The verifiable credentials store could not be read.
    #[error("the verifiable credentials store could not be read")]
    VerifiableCredentialStoreInvalid,

    /// The assertion store does not contain the expected number of assertions.
    #[error(
        "unexpected number of assertions in assertion store (expected {expected}, found {found})"
    )]
    AssertionCountMismatch { expected: usize, found: usize },
}
