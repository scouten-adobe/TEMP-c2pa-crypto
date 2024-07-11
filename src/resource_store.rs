f// Copyright 2023 Adobe. All rights reserved.
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
    borrow::Cow,
    collections::HashMap,
    io::{Read, Seek, Write},
};

use serde::{Deserialize, Serialize};

use crate::{
    assertions::{labels, AssetType},
    claim::Claim,
    hashed_uri::HashedUri,
    jumbf::labels::assertion_label_from_uri,
    Error, Result,
};

/// Function that is used by serde to determine whether or not we should
/// serialize resources based on the `serialize_resources` flag.
/// (Serialization is disabled by default.)
pub(crate) fn skip_serializing_resources(_: &ResourceStore) -> bool {
    !cfg!(feature = "serialize_thumbnails") || cfg!(test) || cfg!(not(target_arch = "wasm32"))
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum UriOrResource {
    ResourceRef(ResourceRef),
    HashedUri(HashedUri),
}
impl UriOrResource {
    pub fn to_hashed_uri(
        &self,
        resources: &ResourceStore,
        claim: &mut Claim,
    ) -> Result<UriOrResource> {
        match self {
            UriOrResource::ResourceRef(r) => {
                let data = resources.get(&r.identifier)?;
                let hash_uri = claim.add_databox(&r.format, data.to_vec(), None)?;
                Ok(UriOrResource::HashedUri(hash_uri))
            }
            UriOrResource::HashedUri(h) => Ok(UriOrResource::HashedUri(h.clone())),
        }
    }

    pub fn to_resource_ref(
        &self,
        resources: &mut ResourceStore,
        claim: &Claim,
    ) -> Result<UriOrResource> {
        match self {
            UriOrResource::ResourceRef(r) => Ok(UriOrResource::ResourceRef(r.clone())),
            UriOrResource::HashedUri(h) => {
                let uri = crate::jumbf::labels::to_absolute_uri(claim.label(), &h.url());
                let data_box = claim.find_databox(&uri).ok_or(Error::MissingDataBox)?;
                let resource_ref =
                    resources.add_with(&h.url(), &data_box.format, data_box.data.clone())?;
                Ok(UriOrResource::ResourceRef(resource_ref))
            }
        }
    }
}

impl From<ResourceRef> for UriOrResource {
    fn from(r: ResourceRef) -> Self {
        Self::ResourceRef(r)
    }
}

impl From<HashedUri> for UriOrResource {
    fn from(h: HashedUri) -> Self {
        Self::HashedUri(h)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
/// A reference to a resource to be used in JSON serialization.
pub struct ResourceRef {
    /// The mime type of the referenced resource.
    pub format: String,

    /// A URI that identifies the resource as referenced from the manifest.
    ///
    /// This may be a JUMBF URI, a file path, a URL or any other string.
    /// Relative JUMBF URIs will be resolved with the manifest label.
    /// Relative file paths will be resolved with the base path if provided.
    pub identifier: String,

    /// More detailed data types as defined in the C2PA spec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_types: Option<Vec<AssetType>>,

    /// The algorithm used to hash the resource (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// The hash of the resource (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl ResourceRef {
    pub fn new<S: Into<String>, I: Into<String>>(format: S, identifier: I) -> Self {
        Self {
            format: format.into(),
            identifier: identifier.into(),
            data_types: None,
            alg: None,
            hash: None,
        }
    }
}

/// Resource store to contain binary objects referenced from JSON serializable
/// structures
#[derive(Debug, Serialize)]
pub struct ResourceStore {
    resources: HashMap<String, Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

impl ResourceStore {
    /// Create a new resource reference.
    pub fn new() -> Self {
        ResourceStore {
            resources: HashMap::new(),
            label: None,
        }
    }

    /// Set a manifest label for this store used to resolve relative JUMBF URIs.
    pub fn set_label<S: Into<String>>(&mut self, label: S) -> &Self {
        self.label = Some(label.into());
        self
    }

    /// Generates a unique ID for a given content type (adds a file extension).
    pub fn id_from(&self, key: &str, format: &str) -> String {
        let ext = match format {
            "jpg" | "jpeg" | "image/jpeg" => ".jpg",
            "c2pa" | "application/x-c2pa-manifest-store" | "application/c2pa" => ".c2pa",
            _ => "",
        };
        // clean string for possible filesystem use
        let id_base = key.replace(['/', ':'], "-");

        // ensure it is unique in this store
        let mut count = 1;
        let mut id = format!("{id_base}{ext}");
        while self.exists(&id) {
            id = format!("{id_base}-{count}{ext}");
            count += 1;
        }
        id
    }

    /// Adds a resource, generating a [`ResourceRef`] from a key and format.
    ///
    /// The generated identifier may be different from the key.
    pub fn add_with<R>(&mut self, key: &str, format: &str, value: R) -> crate::Result<ResourceRef>
    where
        R: Into<Vec<u8>>,
    {
        let id = self.id_from(key, format);
        self.add(&id, value)?;
        Ok(ResourceRef::new(format, id))
    }

    /// Adds a resource, using a given id value.
    pub fn add<S, R>(&mut self, id: S, value: R) -> crate::Result<&mut Self>
    where
        S: Into<String>,
        R: Into<Vec<u8>>,
    {
        self.resources.insert(id.into(), value.into());
        Ok(self)
    }

    /// Returns a [`HashMap`] of internal resources.
    pub fn resources(&self) -> &HashMap<String, Vec<u8>> {
        &self.resources
    }

    /// Returns a copy on write reference to the resource if found.
    ///
    /// Returns [`Error::ResourceNotFound`] if it cannot find a resource
    /// matching that ID.
    pub fn get(&self, id: &str) -> Result<Cow<Vec<u8>>> {
        self.resources.get(id).map_or_else(
            || Err(Error::ResourceNotFound(id.to_string())),
            |v| Ok(Cow::Borrowed(v)),
        )
    }

    pub fn write_stream(
        &self,
        id: &str,
        mut stream: impl Write + Read + Seek + Send,
    ) -> Result<u64> {
        match self.resources().get(id) {
            Some(data) => {
                stream.write_all(data).map_err(Error::IoError)?;
                Ok(data.len() as u64)
            }
            None => Err(Error::ResourceNotFound(id.to_string())),
        }
    }

    /// Returns `true` if the resource has been added or exists as file.
    pub fn exists(&self, id: &str) -> bool {
        self.resources.contains_key(id)
    }
}

impl Default for ResourceStore {
    fn default() -> Self {
        ResourceStore::new()
    }
}

pub fn mime_from_uri(uri: &str) -> String {
    if let Some(label) = assertion_label_from_uri(uri) {
        if label.starts_with(labels::THUMBNAIL) {
            // https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_thumbnail
            if let Some(ext) = label.rsplit('.').next() {
                return format!("image/{ext}");
            }
        }
    }

    // Unknown binary data.
    String::from("application/octet-stream")
}
