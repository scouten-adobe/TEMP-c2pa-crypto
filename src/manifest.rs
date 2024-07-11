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

use std::{borrow::Cow, collections::HashMap, io::Cursor, slice::Iter};

use async_generic::async_generic;
use log::{debug, error};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    assertion::{AssertionBase, AssertionData},
    assertions::{
        labels, Actions, CreativeWork, DataHash, Exif, Metadata, SoftwareAgent, Thumbnail, User,
        UserCbor,
    },
    asset_io::{CAIRead, CAIReadWrite},
    claim::{Claim, RemoteManifest},
    error::{Error, Result},
    hashed_uri::HashedUri,
    ingredient::Ingredient,
    jumbf,
    manifest_assertion::ManifestAssertion,
    resource_store::{mime_from_uri, skip_serializing_resources, ResourceRef, ResourceStore},
    salt::DefaultSalt,
    store::Store,
    AsyncSigner, ClaimGeneratorInfo, HashRange, ManifestAssertionKind, ManifestPatchCallback,
    RemoteSigner, Signer, SigningAlg,
};

/// A Manifest represents all the information in a c2pa manifest
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Manifest {
    /// Optional prefix added to the generated Manifest Label
    /// This is typically Internet domain name for the vendor (i.e. `adobe`)
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor: Option<String>,

    /// A User Agent formatted string identifying the software/hardware/system
    /// produced this claim Spaces are not allowed in names, versions can be
    /// specified with product/1.0 syntax
    #[serde(default = "default_claim_generator")]
    pub claim_generator: String,

    /// A list of claim generator info data identifying the
    /// software/hardware/system produced this claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_generator_info: Option<Vec<ClaimGeneratorInfo>>,

    /// A list of user metadata for this claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Vec<Metadata>>,

    /// A human-readable title, generally source filename.
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,

    /// The format of the source file as a MIME type.
    #[serde(default = "default_format")]
    format: String,

    /// Instance ID from `xmpMM:InstanceID` in XMP metadata.
    #[serde(default = "default_instance_id")]
    instance_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    claim_generator_hints: Option<HashMap<String, Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    thumbnail: Option<ResourceRef>,

    /// A List of ingredients
    #[serde(default = "default_vec::<Ingredient>")]
    ingredients: Vec<Ingredient>,

    /// A List of verified credentials
    #[serde(skip_serializing_if = "Option::is_none")]
    credentials: Option<Vec<Value>>,

    /// A list of assertions
    #[serde(default = "default_vec::<ManifestAssertion>")]
    assertions: Vec<ManifestAssertion>,

    /// A list of assertion hash references.
    #[serde(skip)]
    assertion_references: Vec<HashedUri>,

    /// A list of redactions - URIs to a redacted assertions
    #[serde(skip_serializing_if = "Option::is_none")]
    redactions: Option<Vec<String>>,

    /// Signature data (only used for reporting)
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_info: Option<SignatureInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,

    /// Indicates where a generated manifest goes
    #[serde(skip)]
    remote_manifest: Option<RemoteManifest>,

    /// container for binary assets (like thumbnails)
    #[serde(skip_deserializing)]
    #[serde(skip_serializing_if = "skip_serializing_resources")]
    resources: ResourceStore,
}

fn default_claim_generator() -> String {
    format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

fn default_instance_id() -> String {
    format!("xmp:iid:{}", Uuid::new_v4())
}

fn default_format() -> String {
    "application/octet-stream".to_owned()
}

fn default_vec<T>() -> Vec<T> {
    Vec::new()
}

impl Manifest {
    /// Create a new Manifest
    /// requires a claim_generator string (User Agent))
    pub fn new<S: Into<String>>(claim_generator: S) -> Self {
        Self {
            claim_generator: claim_generator.into(),
            format: default_format(),
            instance_id: default_instance_id(),
            ..Default::default()
        }
    }

    /// Returns a User Agent formatted string identifying the
    /// software/hardware/system produced this claim
    pub fn claim_generator(&self) -> &str {
        self.claim_generator.as_str()
    }

    /// returns the manifest label for this Manifest, as referenced in a
    /// ManifestStore
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Returns a MIME content_type for the asset associated with this manifest.
    pub fn format(&self) -> &str {
        &self.format
    }

    /// Returns the instance identifier.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Returns a user-displayable title for this manifest
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Returns thumbnail tuple with Some((format, bytes)) or None
    pub fn thumbnail(&self) -> Option<(&str, Cow<Vec<u8>>)> {
        self.thumbnail
            .as_ref()
            .and_then(|t| Some(t.format.as_str()).zip(self.resources.get(&t.identifier).ok()))
    }

    /// Returns a thumbnail ResourceRef or `None`.
    pub fn thumbnail_ref(&self) -> Option<&ResourceRef> {
        self.thumbnail.as_ref()
    }

    /// Returns immutable [Ingredient]s used by this Manifest
    /// This can include a parent as well as any placed assets
    pub fn ingredients(&self) -> &[Ingredient] {
        &self.ingredients
    }

    /// Returns mutable [Ingredient]s used by this Manifest
    /// This can include a parent as well as any placed assets
    pub fn ingredients_mut(&mut self) -> &mut [Ingredient] {
        &mut self.ingredients
    }

    /// Returns Assertions for this Manifest
    pub fn assertions(&self) -> &[ManifestAssertion] {
        &self.assertions
    }

    /// Returns raw assertion references
    pub fn assertion_references(&self) -> Iter<HashedUri> {
        self.assertion_references.iter()
    }

    /// Returns Verifiable Credentials
    pub fn credentials(&self) -> Option<&[Value]> {
        self.credentials.as_deref()
    }

    /// Returns the remote_manifest Url if there is one
    /// This is only used when creating a manifest, it will always be None when
    /// reading
    pub fn remote_manifest_url(&self) -> Option<&str> {
        match self.remote_manifest.as_ref() {
            Some(RemoteManifest::Remote(url)) => Some(url.as_str()),
            Some(RemoteManifest::EmbedWithRemote(url)) => Some(url.as_str()),
            _ => None,
        }
    }

    /// Sets the vendor prefix to be used when generating manifest labels
    /// Optional prefix added to the generated Manifest Label
    /// This is typically a lower case Internet domain name for the vendor (i.e.
    /// `adobe`)
    pub fn set_vendor<S: Into<String>>(&mut self, vendor: S) -> &mut Self {
        self.vendor = Some(vendor.into());
        self
    }

    /// Sets the label for this manifest
    /// A label will be generated if this is not called
    /// This is needed if embedding a URL that references the manifest label
    pub fn set_label<S: Into<String>>(&mut self, label: S) -> &mut Self {
        self.label = Some(label.into());
        self
    }

    /// Sets a human readable name for the product that created this manifest
    pub fn set_claim_generator<S: Into<String>>(&mut self, generator: S) -> &mut Self {
        self.claim_generator = generator.into();
        self
    }

    /// Sets a human-readable title for this ingredient.
    pub fn set_format<S: Into<String>>(&mut self, format: S) -> &mut Self {
        self.format = format.into();
        self
    }

    /// Sets a human-readable title for this ingredient.
    pub fn set_instance_id<S: Into<String>>(&mut self, instance_id: S) -> &mut Self {
        self.instance_id = instance_id.into();
        self
    }

    /// Sets a human-readable title for this ingredient.
    pub fn set_title<S: Into<String>>(&mut self, title: S) -> &mut Self {
        self.title = Some(title.into());
        self
    }

    /// Sets the thumbnail from a ResourceRef.
    pub fn set_thumbnail_ref(&mut self, thumbnail: ResourceRef) -> Result<&mut Self> {
        // verify the resource referenced exists
        if thumbnail.format != "none" && !self.resources.exists(&thumbnail.identifier) {
            return Err(Error::NotFound);
        };
        self.thumbnail = Some(thumbnail);
        Ok(self)
    }

    /// Sets the thumbnail format and image data.
    pub fn set_thumbnail<S: Into<String>, B: Into<Vec<u8>>>(
        &mut self,
        format: S,
        thumbnail: B,
    ) -> Result<&mut Self> {
        let base_id = self
            .label()
            .unwrap_or_else(|| self.instance_id())
            .to_string();
        self.thumbnail = Some(
            self.resources
                .add_with(&base_id, &format.into(), thumbnail)?,
        );
        Ok(self)
    }

    /// If set, the embed calls will create a sidecar .c2pa manifest file next
    /// to the output file No change will be made to the output file
    pub fn set_sidecar_manifest(&mut self) -> &mut Self {
        self.remote_manifest = Some(RemoteManifest::SideCar);
        self
    }

    /// If set, the embed calls will put the remote url into the output file xmp
    /// provenance and create a c2pa manifest file next to the output file
    pub fn set_remote_manifest<S: Into<String>>(&mut self, remote_url: S) -> &mut Self {
        self.remote_manifest = Some(RemoteManifest::Remote(remote_url.into()));
        self
    }

    /// If set, the embed calls will put the remote url into the output file xmp
    /// provenance and will embed the manifest into the output file
    pub fn set_embedded_manifest_with_remote_ref<S: Into<String>>(
        &mut self,
        remote_url: S,
    ) -> &mut Self {
        self.remote_manifest = Some(RemoteManifest::EmbedWithRemote(remote_url.into()));
        self
    }

    pub fn signature_info(&self) -> Option<&SignatureInfo> {
        self.signature_info.as_ref()
    }

    /// Returns the parent ingredient if it exists
    pub fn parent(&self) -> Option<&Ingredient> {
        self.ingredients.iter().find(|i| i.is_parent())
    }

    /// Sets the parent ingredient, assuring it is first and setting the
    /// is_parent flag
    pub fn set_parent(&mut self, mut ingredient: Ingredient) -> Result<&mut Self> {
        // there should only be one parent so return an error if we already have one
        if self.parent().is_some() {
            error!("parent already added");
            return Err(Error::BadParam("Parent parent already added".to_owned()));
        }
        ingredient.set_is_parent();
        self.ingredients.insert(0, ingredient);

        Ok(self)
    }

    /// Add an ingredient removing duplicates (consumes the asset)
    pub fn add_ingredient(&mut self, ingredient: Ingredient) -> &mut Self {
        self.ingredients.push(ingredient);
        self
    }

    /// Adds assertion using given label and any serde serializable
    /// The data for predefined assertions must be in correct format
    ///
    /// # Example: Creating a custom assertion from a serde_json object.
    ///```
    /// # use c2pa_crypto::Result;
    /// use c2pa_crypto::Manifest;
    /// use serde_json::json;
    /// # fn main() -> Result<()> {
    /// let mut manifest = Manifest::new("my_app");
    /// let value = json!({"my_tag": "Anything I want"});
    /// manifest.add_labeled_assertion("org.contentauth.foo", &value)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_labeled_assertion<S: Into<String>, T: Serialize>(
        &mut self,
        label: S,
        data: &T,
    ) -> Result<&mut Self> {
        self.assertions
            .push(ManifestAssertion::from_labeled_assertion(label, data)?);
        Ok(self)
    }

    /// TO DO: Add docs
    pub fn add_cbor_assertion<S: Into<String>, T: Serialize>(
        &mut self,
        label: S,
        data: &T,
    ) -> Result<&mut Self> {
        self.assertions
            .push(ManifestAssertion::from_cbor_assertion(label, data)?);
        Ok(self)
    }

    pub fn add_assertion<T: Serialize + AssertionBase>(&mut self, data: &T) -> Result<&mut Self> {
        self.assertions
            .push(ManifestAssertion::from_assertion(data)?);
        Ok(self)
    }

    pub fn find_assertion<T: DeserializeOwned>(&self, label: &str) -> Result<T> {
        if let Some(manifest_assertion) = self.assertions.iter().find(|a| a.label() == label) {
            manifest_assertion.to_assertion()
        } else {
            Err(Error::NotFound)
        }
    }

    /// Retrieves an assertion by label and instance if it exists or
    /// Error::NotFound
    pub fn find_assertion_with_instance<T: DeserializeOwned>(
        &self,
        label: &str,
        instance: usize,
    ) -> Result<T> {
        if let Some(manifest_assertion) = self
            .assertions
            .iter()
            .find(|a| a.label() == label && a.instance() == instance)
        {
            manifest_assertion.to_assertion()
        } else {
            Err(Error::NotFound)
        }
    }

    /// Redacts an assertion from the parent [Ingredient] of this manifest using
    /// the provided assertion label.
    pub fn add_redaction<S: Into<String>>(&mut self, label: S) -> Result<&mut Self> {
        // todo: any way to verify if this assertion exists in the parent claim here?
        match self.redactions.as_mut() {
            Some(redactions) => redactions.push(label.into()),
            None => self.redactions = Some([label.into()].to_vec()),
        }
        Ok(self)
    }

    /// Add verifiable credentials
    pub fn add_verifiable_credential<T: Serialize>(&mut self, data: &T) -> Result<&mut Self> {
        let value = serde_json::to_value(data).map_err(|_err| Error::AssertionEncoding)?;
        match self.credentials.as_mut() {
            Some(credentials) => credentials.push(value),
            None => self.credentials = Some([value].to_vec()),
        }
        Ok(self)
    }

    /// Returns the name of the signature issuer
    pub fn issuer(&self) -> Option<String> {
        self.signature_info.to_owned().and_then(|sig| sig.issuer)
    }

    /// Returns the time that the manifest was signed
    pub fn time(&self) -> Option<String> {
        self.signature_info.to_owned().and_then(|sig| sig.time)
    }

    /// Returns an iterator over [`ResourceRef`][ResourceRef]s.
    pub fn iter_resources(&self) -> impl Iterator<Item = ResourceRef> + '_ {
        self.resources
            .resources()
            .keys()
            .map(|uri| ResourceRef::new(mime_from_uri(uri), uri.to_owned()))
    }

    /// Return an immutable reference to the manifest resources
    pub fn resources(&self) -> &ResourceStore {
        &self.resources
    }

    /// Return a mutable reference to the manifest resources
    pub fn resources_mut(&mut self) -> &mut ResourceStore {
        &mut self.resources
    }

    /// Creates a Manifest from a JSON string formatted as a Manifest
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_slice(json.as_bytes()).map_err(Error::JsonError)
    }

    // Generates a Manifest given a store and a manifest label
    pub(crate) fn from_store(store: &Store, manifest_label: &str) -> Result<Self> {
        let claim = store
            .get_claim(manifest_label)
            .ok_or_else(|| Error::ClaimMissing {
                label: manifest_label.to_owned(),
            })?;

        // extract vendor from claim label
        let claim_generator = claim.claim_generator().to_owned();

        let mut manifest = Manifest::new(claim_generator);

        if let Some(info_vec) = claim.claim_generator_info() {
            let mut generators = Vec::new();
            for claim_info in info_vec {
                let mut info = claim_info.to_owned();
                if let Some(icon) = claim_info.icon.as_ref() {
                    info.set_icon(icon.to_resource_ref(manifest.resources_mut(), claim)?);
                }
                generators.push(info);
            }
            manifest.claim_generator_info = Some(generators);
        }

        if let Some(metadata_vec) = claim.metadata() {
            if !metadata_vec.is_empty() {
                manifest.metadata = Some(metadata_vec.to_vec())
            }
        }

        manifest.set_label(claim.label());
        manifest.resources.set_label(claim.label()); // default manifest for relative urls
        manifest.claim_generator_hints = claim.get_claim_generator_hint_map().cloned();

        // get credentials converting from AssertionData to Value
        let credentials: Vec<Value> = claim
            .get_verifiable_credentials()
            .iter()
            .filter_map(|d| match d {
                AssertionData::Json(s) => serde_json::from_str(s).ok(),
                _ => None,
            })
            .collect();

        if !credentials.is_empty() {
            manifest.credentials = Some(credentials);
        }

        manifest.redactions = claim.redactions().map(|rs| {
            rs.iter()
                .filter_map(|r| jumbf::labels::assertion_label_from_uri(r))
                .collect()
        });

        if let Some(title) = claim.title() {
            manifest.set_title(title);
        }
        manifest.set_format(claim.format());
        manifest.set_instance_id(claim.instance_id());

        manifest.assertion_references = claim
            .assertions()
            .iter()
            .map(|h| {
                let alg = h.alg().or_else(|| Some(claim.alg().to_string()));
                HashedUri::new(h.url(), alg, &h.hash())
            })
            .collect();

        for assertion in claim.assertions() {
            let claim_assertion = store.get_claim_assertion_from_uri(
                &jumbf::labels::to_absolute_uri(claim.label(), &assertion.url()),
            )?;
            let assertion = claim_assertion.assertion();
            let label = claim_assertion.label();
            let base_label = assertion.label();
            debug!("assertion = {}", &label);
            match base_label.as_ref() {
                base if base.starts_with(labels::ACTIONS) => {
                    let mut actions = Actions::from_assertion(assertion)?;

                    for action in actions.actions_mut() {
                        if let Some(SoftwareAgent::ClaimGeneratorInfo(info)) =
                            action.software_agent_mut()
                        {
                            if let Some(icon) = info.icon.as_mut() {
                                let icon = icon.to_resource_ref(manifest.resources_mut(), claim)?;
                                info.set_icon(icon);
                            }
                        }
                    }

                    // convert icons in templates to resource refs
                    if let Some(templates) = actions.templates.as_mut() {
                        for template in templates {
                            // replace icon with resource ref
                            template.icon = match template.icon.take() {
                                Some(icon) => {
                                    Some(icon.to_resource_ref(manifest.resources_mut(), claim)?)
                                }
                                None => None,
                            };

                            // replace software agent with resource ref
                            template.software_agent = match template.software_agent.take() {
                                Some(SoftwareAgent::ClaimGeneratorInfo(mut info)) => {
                                    if let Some(icon) = info.icon.as_mut() {
                                        let icon =
                                            icon.to_resource_ref(manifest.resources_mut(), claim)?;
                                        info.set_icon(icon);
                                    }
                                    Some(SoftwareAgent::ClaimGeneratorInfo(info))
                                }
                                agent => agent,
                            };
                        }
                    }
                    let manifest_assertion = ManifestAssertion::from_assertion(&actions)?
                        .set_instance(claim_assertion.instance());
                    manifest.assertions.push(manifest_assertion);
                }
                base if base.starts_with(labels::INGREDIENT) => {
                    // note that we use the original label here, not the base label
                    let assertion_uri = jumbf::labels::to_assertion_uri(claim.label(), &label);
                    let ingredient =
                        Ingredient::from_ingredient_uri(store, manifest_label, &assertion_uri)?;
                    manifest.add_ingredient(ingredient);
                }
                labels::DATA_HASH | labels::BOX_HASH => {
                    // do not include data hash when reading manifests
                }
                label if label.starts_with(labels::CLAIM_THUMBNAIL) => {
                    let thumbnail = Thumbnail::from_assertion(assertion)?;
                    let id = jumbf::labels::to_assertion_uri(claim.label(), label);
                    let id = jumbf::labels::to_relative_uri(&id);
                    manifest.thumbnail = Some(manifest.resources.add_uri(
                        &id,
                        &thumbnail.content_type,
                        thumbnail.data,
                    )?);
                }
                _ => {
                    // inject assertions for all other assertions
                    match assertion.decode_data() {
                        AssertionData::Cbor(_) => {
                            let value = assertion.as_json_object()?;
                            let ma = ManifestAssertion::new(base_label, value)
                                .set_instance(claim_assertion.instance());

                            manifest.assertions.push(ma);
                        }
                        AssertionData::Json(_) => {
                            let value = assertion.as_json_object()?;
                            let ma = ManifestAssertion::new(base_label, value)
                                .set_instance(claim_assertion.instance())
                                .set_kind(ManifestAssertionKind::Json);

                            manifest.assertions.push(ma);
                        }

                        // todo: support binary forms
                        AssertionData::Binary(_x) => {}
                        AssertionData::Uuid(_, _) => {}
                    }
                }
            }
        }

        manifest.signature_info = match claim.signature_info() {
            Some(signature_info) => Some(SignatureInfo {
                alg: signature_info.alg,
                issuer: signature_info.issuer_org,
                time: signature_info.date.map(|d| d.to_rfc3339()),
                cert_serial_number: signature_info.cert_serial_number.map(|s| s.to_string()),
                cert_chain: String::from_utf8(signature_info.cert_chain)
                    .map_err(|_e| Error::CoseInvalidCert)?,
                revocation_status: signature_info.revocation_status,
            }),
            None => None,
        };

        Ok(manifest)
    }

    // Convert a Manifest into a Claim
    pub(crate) fn to_claim(&self) -> Result<Claim> {
        // add library identifier to claim_generator
        let generator = format!(
            "{} {}/{}",
            &self.claim_generator,
            crate::NAME,
            crate::VERSION
        );

        let mut claim = match self.label() {
            Some(label) => Claim::new_with_user_guid(&generator, &label.to_string()),
            None => Claim::new(&generator, self.vendor.as_deref()),
        };

        if let Some(info_vec) = self.claim_generator_info.as_ref() {
            for info in info_vec {
                let mut claim_info = info.to_owned();
                if let Some(icon) = claim_info.icon.as_ref() {
                    claim_info.icon = Some(icon.to_hashed_uri(self.resources(), &mut claim)?);
                }
                claim.add_claim_generator_info(claim_info);
            }
        }

        if let Some(metadata_vec) = self.metadata.as_ref() {
            for metadata in metadata_vec {
                claim.add_claim_metadata(metadata.to_owned());
            }
        }

        if let Some(remote_op) = &self.remote_manifest {
            match remote_op {
                RemoteManifest::NoRemote => (),
                RemoteManifest::SideCar => claim.set_external_manifest(),
                RemoteManifest::Remote(r) => claim.set_remote_manifest(r)?,
                RemoteManifest::EmbedWithRemote(r) => claim.set_embed_remote_manifest(r)?,
            };
        }

        if let Some(title) = self.title() {
            claim.set_title(Some(title.to_owned()));
        }
        self.format().clone_into(&mut claim.format);
        self.instance_id().clone_into(&mut claim.instance_id);

        if let Some(thumb_ref) = self.thumbnail_ref() {
            // Setting the format to "none" will ensure that no claim thumbnail is added
            if thumb_ref.format != "none" {
                let data = self.resources.get(&thumb_ref.identifier)?;
                claim.add_assertion(&Thumbnail::new(
                    &labels::add_thumbnail_format(labels::CLAIM_THUMBNAIL, &thumb_ref.format),
                    data.into_owned(),
                ))?;
            }
        }

        // add any verified credentials - needs to happen early so we can reference them
        let mut vc_table = HashMap::new();
        if let Some(verified_credentials) = self.credentials.as_ref() {
            for vc in verified_credentials {
                let vc_str = &vc.to_string();
                let id = Claim::vc_id(vc_str)?;
                vc_table.insert(id, claim.add_verifiable_credential(vc_str)?);
            }
        }

        let mut ingredient_map = HashMap::new();
        // add all ingredients to the claim
        for ingredient in &self.ingredients {
            let uri = ingredient.add_to_claim(&mut claim, self.redactions.clone(), None)?;
            ingredient_map.insert(ingredient.instance_id(), uri);
        }

        let salt = DefaultSalt::default();

        // add any additional assertions
        for manifest_assertion in &self.assertions {
            match manifest_assertion.label() {
                l if l.starts_with(Actions::LABEL) => {
                    let version = labels::version(l);

                    let mut actions: Actions = manifest_assertion.to_assertion()?;

                    let ingredients_key = match version {
                        None | Some(1) => "ingredient",
                        Some(2) => "ingredients",
                        _ => return Err(Error::AssertionUnsupportedVersion),
                    };

                    // fixup parameters field from instance_id to ingredient uri
                    let needs_ingredient: Vec<(usize, crate::assertions::Action)> = actions
                        .actions()
                        .iter()
                        .enumerate()
                        .filter_map(|(i, a)| {
                            if a.instance_id().is_some()
                                && a.get_parameter(ingredients_key).is_none()
                            {
                                Some((i, a.clone()))
                            } else {
                                None
                            }
                        })
                        .collect();

                    for (index, action) in needs_ingredient {
                        if let Some(id) = action.instance_id() {
                            if let Some(hash_url) = ingredient_map.get(id) {
                                let update = match ingredients_key {
                                    "ingredient" => {
                                        action.set_parameter(ingredients_key, hash_url.clone())
                                    }
                                    _ => {
                                        // we only support on instanceId for actions, so only one
                                        // ingredient on writing
                                        action.set_parameter(ingredients_key, [hash_url.clone()])
                                    }
                                }?;
                                actions = actions.update_action(index, update);
                            }
                        }
                    }

                    if let Some(templates) = actions.templates.as_mut() {
                        for template in templates {
                            // replace icon with hashed_uri
                            template.icon = match template.icon.take() {
                                Some(icon) => {
                                    Some(icon.to_hashed_uri(self.resources(), &mut claim)?)
                                }
                                None => None,
                            };

                            // replace software agent with hashed_uri
                            template.software_agent = match template.software_agent.take() {
                                Some(SoftwareAgent::ClaimGeneratorInfo(mut info)) => {
                                    if let Some(icon) = info.icon.as_mut() {
                                        let icon =
                                            icon.to_hashed_uri(self.resources(), &mut claim)?;
                                        info.set_icon(icon);
                                    }
                                    Some(SoftwareAgent::ClaimGeneratorInfo(info))
                                }
                                agent => agent,
                            };
                        }
                    }

                    // convert icons in software agents to hashed uris
                    let actions_mut = actions.actions_mut();
                    #[allow(clippy::needless_range_loop)]
                    // clippy is wrong here, we reference index twice
                    for index in 0..actions_mut.len() {
                        let action = &actions_mut[index];
                        if let Some(SoftwareAgent::ClaimGeneratorInfo(info)) =
                            action.software_agent()
                        {
                            if let Some(icon) = info.icon.as_ref() {
                                let mut info = info.to_owned();
                                let icon_uri = icon.to_hashed_uri(self.resources(), &mut claim)?;
                                let update = info.set_icon(icon_uri);
                                let mut action = action.to_owned();
                                action = action.set_software_agent(update.to_owned());
                                actions_mut[index] = action;
                            }
                        }
                    }

                    claim.add_assertion(&actions)
                }
                CreativeWork::LABEL => {
                    let mut cw: CreativeWork = manifest_assertion.to_assertion()?;
                    // insert a credentials field if we have a vc that matches the identifier
                    // todo: this should apply to any person, not just author
                    if let Some(cw_authors) = cw.author() {
                        let mut authors = Vec::new();
                        for a in cw_authors {
                            authors.push(
                                a.identifier()
                                    .and_then(|i| {
                                        vc_table
                                            .get(&i)
                                            .map(|uri| a.clone().add_credential(uri.clone()))
                                    })
                                    .unwrap_or_else(|| Ok(a.clone()))?,
                            );
                        }
                        cw = cw.set_author(&authors)?;
                    }
                    claim.add_assertion_with_salt(&cw, &salt)
                }
                Exif::LABEL => {
                    let exif: Exif = manifest_assertion.to_assertion()?;
                    claim.add_assertion_with_salt(&exif, &salt)
                }
                _ => match manifest_assertion.kind() {
                    ManifestAssertionKind::Cbor => {
                        let cbor = match manifest_assertion.value() {
                            Ok(value) => serde_cbor::to_vec(value)?,
                            Err(_) => manifest_assertion.binary()?.to_vec(),
                        };

                        claim.add_assertion_with_salt(
                            &UserCbor::new(manifest_assertion.label(), cbor),
                            &salt,
                        )
                    }
                    ManifestAssertionKind::Json => claim.add_assertion_with_salt(
                        &User::new(
                            manifest_assertion.label(),
                            &serde_json::to_string(&manifest_assertion.value()?)?,
                        ),
                        &salt,
                    ),
                    ManifestAssertionKind::Binary => {
                        // todo: Support binary kinds
                        return Err(Error::AssertionEncoding);
                    }
                    ManifestAssertionKind::Uri => {
                        // todo: Support binary kinds
                        return Err(Error::AssertionEncoding);
                    }
                },
            }?;
        }

        Ok(claim)
    }

    // Convert a Manifest into a Store
    pub(crate) fn to_store(&self) -> Result<Store> {
        let claim = self.to_claim()?;
        // commit the claim
        let mut store = Store::new();
        let _provenance = store.commit_claim(claim)?;
        Ok(store)
    }

    /// Embed a signed manifest into a stream using a supplied signer.
    /// returns the bytes of the  manifest that was embedded
    #[async_generic(async_signature(
        &mut self,
        format: &str,
        asset: &[u8],
        signer: &dyn AsyncSigner,
    ))]
    pub fn embed_from_memory(
        &mut self,
        format: &str,
        asset: &[u8],
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        // first make a copy of the asset that will contain our modified result
        // todo:: see if we can pass a trait with to_vec support like we to for Strings
        let asset = asset.to_vec();
        let mut stream = std::io::Cursor::new(asset);
        let mut output_stream = Cursor::new(Vec::new());
        if _sync {
            self.embed_to_stream(format, &mut stream, &mut output_stream, signer)?;
        } else {
            self.embed_to_stream_async(format, &mut stream, &mut output_stream, signer)
                .await?;
        }
        Ok(output_stream.into_inner())
    }

    /// Embed a signed manifest into a stream using a supplied signer.
    ///
    /// Returns the bytes of the new asset
    #[deprecated(since = "0.27.2", note = "use embed_to_stream instead")]
    pub fn embed_stream(
        &mut self,
        format: &str,
        stream: &mut dyn CAIRead,
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        // sign and write our store to to the output image file
        let output_vec: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output_vec);

        self.embed_to_stream(format, stream, &mut output_stream, signer)?;

        Ok(output_stream.into_inner())
    }

    /// Embed a signed manifest into a stream using a supplied signer.
    ///
    /// Returns the bytes of c2pa_manifest that was embedded.
    #[async_generic(async_signature(
        &mut self,
        format: &str,
        source: &mut dyn CAIRead,
        dest: &mut dyn CAIReadWrite,
        signer: &dyn AsyncSigner,
    ))]
    pub fn embed_to_stream(
        &mut self,
        format: &str,
        source: &mut dyn CAIRead,
        dest: &mut dyn CAIReadWrite,
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        self.set_format(format);
        // todo:: read instance_id from xmp from stream
        self.set_instance_id(format!("xmp:iid:{}", Uuid::new_v4()));

        // convert the manifest to a store
        let mut store = self.to_store()?;

        // sign and write our store to to the output image file
        if _sync {
            store.save_to_stream(format, source, dest, signer)
        } else {
            store
                .save_to_stream_async(format, source, dest, signer)
                .await
        }
    }

    /// Embed a signed manifest into a stream using a supplied signer.
    /// returns the  asset generated and bytes of the manifest that was embedded
    //#[cfg(feature = "remote_wasm_sign")]
    pub async fn embed_from_memory_remote_signed(
        &mut self,
        format: &str,
        asset: &[u8],
        signer: &dyn RemoteSigner,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        self.set_format(format);
        // todo:: read instance_id from xmp from stream
        self.set_instance_id(format!("xmp:iid:{}", Uuid::new_v4()));

        // generate thumbnail if we don't already have one
        #[allow(unused_mut)] // so that this builds with WASM
        let mut stream = std::io::Cursor::new(asset);
        let asset = stream.into_inner();

        // convert the manifest to a store
        let mut store = self.to_store()?;

        // sign and write our store to to the output image file
        let (output_asset, output_manifest) = store
            .save_to_memory_remote_signed(format, asset, signer)
            .await?;

        Ok((output_asset, output_manifest))
    }

    /// Generates a data hashed placeholder manifest for a file
    ///
    /// The return value is pre-formatted for insertion into a file of the given
    /// format For JPEG it is a series of App11 JPEG segments containing
    /// space for a manifest This is used to create a properly formatted
    /// file ready for signing. The reserve_size is the amount of space to
    /// reserve for the signature box.  This value is fixed once set and
    /// must be sufficient to hold the completed signature
    pub fn data_hash_placeholder(&mut self, reserve_size: usize, format: &str) -> Result<Vec<u8>> {
        let dh: Result<DataHash> = self.find_assertion(DataHash::LABEL);
        if dh.is_err() {
            let mut ph = DataHash::new("jumbf manifest", "sha256");
            for _ in 0..10 {
                ph.add_exclusion(HashRange::new(0, 2));
            }
            self.add_assertion(&ph)?;
        }

        let mut store = self.to_store()?;
        let placeholder = store.get_data_hashed_manifest_placeholder(reserve_size, format)?;
        Ok(placeholder)
    }

    /// Generates an data hashed embeddable manifest for a file
    ///
    /// The return value is pre-formatted for insertion into a file of the given
    /// format For JPEG it is a series of App11 JPEG segments containing a
    /// signed manifest This can directly replace a placeholder manifest to
    /// create a properly signed asset The data hash must contain exclusions
    /// and may contain pre-calculated hashes if an asset reader is
    /// provided, it will be used to calculate the data hash
    #[async_generic(async_signature(
        &mut self,
        dh: &DataHash,
        signer: &dyn AsyncSigner,
        format: &str,
        mut asset_reader: Option<&mut dyn CAIRead>,
    ))]
    pub fn data_hash_embeddable_manifest(
        &mut self,
        dh: &DataHash,
        signer: &dyn Signer,
        format: &str,
        mut asset_reader: Option<&mut dyn CAIRead>,
    ) -> Result<Vec<u8>> {
        let mut store = self.to_store()?;
        if let Some(asset_reader) = asset_reader.as_deref_mut() {
            asset_reader.rewind()?;
        }
        if _sync {
            store.get_data_hashed_embeddable_manifest(dh, signer, format, asset_reader)
        } else {
            store
                .get_data_hashed_embeddable_manifest_async(dh, signer, format, asset_reader)
                .await
        }
    }

    /// Generates an data hashed embeddable manifest for a file
    ///
    /// The return value is pre-formatted for insertion into a file of the given
    /// format For JPEG it is a series of App11 JPEG segments containing a
    /// signed manifest This can directly replace a placeholder manifest to
    /// create a properly signed asset The data hash must contain exclusions
    /// and may contain pre-calculated hashes if an asset reader is
    /// provided, it will be used to calculate the data hash
    pub async fn data_hash_embeddable_manifest_remote(
        &mut self,
        dh: &DataHash,
        signer: &dyn RemoteSigner,
        format: &str,
        mut asset_reader: Option<&mut dyn CAIRead>,
    ) -> Result<Vec<u8>> {
        let mut store = self.to_store()?;
        if let Some(asset_reader) = asset_reader.as_deref_mut() {
            asset_reader.rewind()?;
        }
        store
            .get_data_hashed_embeddable_manifest_remote(dh, signer, format, asset_reader)
            .await
    }

    /// Generates a signed box hashed manifest, optionally preformatted for
    /// embedding
    ///
    /// The manifest must include a box hash assertion with correct hashes
    #[async_generic(async_signature(
        &mut self,
        signer: &dyn AsyncSigner,
        format: Option<&str>,
    ))]
    pub fn box_hash_embeddable_manifest(
        &mut self,
        signer: &dyn Signer,
        format: Option<&str>,
    ) -> Result<Vec<u8>> {
        let mut store = self.to_store()?;
        let mut cm = if _sync {
            store.get_box_hashed_embeddable_manifest(signer)
        } else {
            store.get_box_hashed_embeddable_manifest_async(signer).await
        }?;
        if let Some(format) = format {
            cm = Store::get_composed_manifest(&cm, format)?;
        }
        Ok(cm)
    }

    /// Formats a signed manifest for embedding in the given format
    ///
    /// For instance, this would return one or JPEG App11 segments containing
    /// the manifest
    pub fn composed_manifest(manifest_bytes: &[u8], format: &str) -> Result<Vec<u8>> {
        Store::get_composed_manifest(manifest_bytes, format)
    }

    /// Generate a placed manifest.  The returned manifest is complete
    /// as if it were inserted into the asset specified by input_stream
    /// expect that it has not been placed into an output asset and has not
    /// been signed.  Use embed_placed_manifest to insert into the asset
    /// referenced by input_stream
    pub fn get_placed_manifest(
        &mut self,
        reserve_size: usize,
        format: &str,
        input_stream: &mut dyn CAIRead,
    ) -> Result<(Vec<u8>, String)> {
        let mut store = self.to_store()?;

        Ok((
            store.get_placed_manifest(reserve_size, format, input_stream)?,
            store.provenance_label().ok_or(Error::NotFound)?,
        ))
    }

    /// Signs and embeds the manifest specified by manifest_bytes into
    /// output_stream. format specifies the format of the asset. The
    /// input_stream should point to the same asset
    /// used in get_placed_manifest.  The caller can supply list of
    /// ManifestPathCallback traits to make any modifications to assertions.
    /// The callbacks are processed before the manifest is signed.  
    pub fn embed_placed_manifest(
        manifest_bytes: &[u8],
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        signer: &dyn Signer,
        manifest_callbacks: &[Box<dyn ManifestPatchCallback>],
    ) -> Result<Vec<u8>> {
        Store::embed_placed_manifest(
            manifest_bytes,
            format,
            input_stream,
            output_stream,
            signer,
            manifest_callbacks,
        )
    }
}

impl std::fmt::Display for Manifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        f.write_str(&json)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
/// Holds information about a signature
pub struct SignatureInfo {
    /// human readable issuing authority for this signature
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<SigningAlg>,
    /// human readable issuing authority for this signature
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,

    /// The serial number of the certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_serial_number: Option<String>,

    /// the time the signature was created
    #[serde(skip_serializing_if = "Option::is_none")]
    time: Option<String>,

    /// the cert chain for this claim
    #[serde(skip)] // don't serialize this, let someone ask for it
    cert_chain: String,

    /// revocation status of the certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_status: Option<bool>,
}

impl SignatureInfo {
    // returns the cert chain for this signature
    pub fn cert_chain(&self) -> &str {
        &self.cert_chain
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    use crate::{
        assertions::{c2pa_action, Action, Actions},
        utils::test::{temp_signer, TEST_VC},
        Manifest, Result,
    };

    // example of random data structure as an assertion
    #[derive(serde::Serialize)]
    #[allow(dead_code)] // this here for wasm builds to pass clippy  (todo: remove)
    struct MyStruct {
        l1: String,
        l2: u32,
    }

    fn test_manifest() -> Manifest {
        Manifest::new("test".to_owned())
    }

    #[test]
    fn test_verifiable_credential() {
        let mut manifest = test_manifest();
        let vc: serde_json::Value = serde_json::from_str(TEST_VC).unwrap();
        manifest
            .add_verifiable_credential(&vc)
            .expect("verifiable_credential");
        let store = manifest.to_store().expect("to_store");
        let claim = store.provenance_claim().unwrap();
        assert!(!claim.get_verifiable_credentials().is_empty());
    }

    #[test]
    fn test_assertion_user_cbor() {
        use crate::{assertions::UserCbor, Manifest};

        const LABEL: &str = "org.cai.test";
        const DATA: &str = r#"{ "l1":"some data", "l2":"some other data" }"#;
        let json: serde_json::Value = serde_json::from_str(DATA).unwrap();
        let data = serde_cbor::to_vec(&json).unwrap();
        let cbor = UserCbor::new(LABEL, data);
        let mut manifest = test_manifest();
        manifest.add_assertion(&cbor).expect("add_assertion");
        manifest.add_assertion(&cbor).expect("add_assertion");
        let store = manifest.to_store().expect("to_store");

        let _manifest2 =
            Manifest::from_store(&store, &store.provenance_label().unwrap()).expect("from_store");
        println!("{store}");
        println!("{_manifest2:?}");
        let cbor2: UserCbor = manifest.find_assertion(LABEL).expect("get_assertion");
        assert_eq!(cbor, cbor2);
    }

    #[test]
    fn manifest_assertion_instances() {
        let mut manifest = Manifest::new("test".to_owned());
        let actions = Actions::new().add_action(Action::new(c2pa_action::EDITED));
        // add three assertions with the same label
        manifest.add_assertion(&actions).expect("add_assertion");
        manifest.add_assertion(&actions).expect("add_assertion");
        manifest.add_assertion(&actions).expect("add_assertion");

        // convert to a store and read back again
        let store = manifest.to_store().expect("to_store");
        println!("{store}");
        let active_label = store.provenance_label().unwrap();

        let manifest2 = Manifest::from_store(&store, &active_label).expect("from_store");
        println!("{manifest2}");

        // now check to see if we have three separate assertions with different
        // instances
        let action2: Result<Actions> = manifest2.find_assertion_with_instance(Actions::LABEL, 2);
        assert!(action2.is_ok());
        assert_eq!(action2.unwrap().actions()[0].action(), c2pa_action::EDITED);
    }

    #[test]
    fn test_missing_thumbnail() {
        const MANIFEST_JSON: &str = r#"
            {
                "claim_generator": "test",
                "format" : "image/jpeg",
                "thumbnail": {
                    "format": "image/jpeg",
                    "identifier": "does_not_exist.jpg"
                }
            }
        "#;

        let mut manifest = Manifest::from_json(MANIFEST_JSON).expect("from_json");

        let mut source = std::io::Cursor::new(vec![1, 2, 3]);
        let mut dest = std::io::Cursor::new(Vec::new());
        let signer = temp_signer();
        let result =
            manifest.embed_to_stream("image/jpeg", &mut source, &mut dest, signer.as_ref());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("resource not found: does_not_exist.jpg"));
    }
}
