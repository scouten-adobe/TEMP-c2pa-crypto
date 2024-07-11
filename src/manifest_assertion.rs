use serde::{de::DeserializeOwned, Deserialize, Serialize}; //,  Deserializer, Serializer};
use serde_json::Value;

use crate::{
    assertion::{AssertionBase, AssertionDecodeError},
    error::{Error, Result},
};

/// Assertions in C2PA can be stored in several formats
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub enum ManifestAssertionKind {
    Cbor,
    Json,
    Binary,
    Uri,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
enum ManifestData {
    Json(Value),     // { label: String, instance: usize, data: Value },
    Binary(Vec<u8>), // ) { label: String, instance: usize, data: Value },
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// A labeled container for an Assertion value in a Manifest
pub struct ManifestAssertion {
    /// An assertion label in reverse domain format
    label: String,
    /// The data of the assertion as Value
    data: ManifestData,
    /// There can be more than one assertion for any label
    #[serde(skip_serializing_if = "Option::is_none")]
    instance: Option<usize>,
    /// The [ManifestAssertionKind] for this assertion (as stored in c2pa
    /// content)
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<ManifestAssertionKind>,
}

impl ManifestAssertion {
    /// Create with label and value
    pub fn new(label: String, data: Value) -> Self {
        Self {
            label,
            data: ManifestData::Json(data),
            instance: None,
            kind: None,
        }
    }

    /// An assertion label in reverse domain format
    pub fn label(&self) -> &str {
        &self.label
    }

    /// An assertion label in reverse domain format with appended instance
    /// number The instance number follows two underscores and is only added
    /// when the instance is > 1 This is a c2pa spec internal standard
    /// format
    pub fn label_with_instance(&self) -> String {
        match self.instance {
            Some(i) if i > 1 => format!("{}__{}", self.label, i),
            _ => self.label.to_owned(),
        }
    }

    /// The data of the assertion as a serde_Json::Value
    /// This will return UnsupportedType if the assertion data is binary
    pub fn value(&self) -> Result<&Value> {
        match &self.data {
            ManifestData::Json(d) => Ok(d),
            ManifestData::Binary(_) => Err(Error::UnsupportedType),
        }
    }

    /// The data of the assertion as u8 binary vector
    /// This will return UnsupportedType if the assertion data is Json/String
    pub fn binary(&self) -> Result<&[u8]> {
        match &self.data {
            ManifestData::Json(_) => Err(Error::UnsupportedType),
            ManifestData::Binary(b) => Ok(b),
        }
    }

    /// The instance number of this assertion
    /// If the same label is used for multiple assertions, incremental instances
    /// are added The first instance is always 1 and increased by 1 per
    /// duplicated label
    pub fn instance(&self) -> usize {
        self.instance.unwrap_or(1)
    }

    /// The ManifestAssertionKind for this assertion
    /// This refers to how the format of the assertion inside a C2PA manifest
    /// The default is ManifestAssertionKind::Cbor
    pub fn kind(&self) -> &ManifestAssertionKind {
        match self.kind.as_ref() {
            Some(kind) => kind,
            None => &ManifestAssertionKind::Cbor,
        }
    }

    /// Allows overriding the default [ManifestAssertionKind] to Json
    /// For assertions like Schema.org that require being stored in Json format
    pub fn set_kind(mut self, kind: ManifestAssertionKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Creates a ManifestAssertion with the given label and any serde
    /// serializable object
    ///
    /// # Example: Creating a custom assertion from a serde_json object.
    ///
    ///```
    /// # use c2pa_crypto::Result;
    /// use c2pa_crypto::ManifestAssertion;
    /// use serde_json::json;
    /// # fn main() -> Result<()> {
    /// let value = json!({"my_tag": "Anything I want"});
    /// let _ma = ManifestAssertion::from_labeled_assertion("org.contentauth.foo", &value)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_labeled_assertion<S: Into<String>, T: Serialize>(
        label: S,
        data: &T,
    ) -> Result<Self> {
        Ok(Self::new(
            label.into(),
            serde_json::to_value(data).map_err(|_err| Error::AssertionEncoding)?,
        ))
    }

    /// TO DO: Docs ...
    pub fn from_cbor_assertion<S: Into<String>, T: Serialize>(label: S, data: &T) -> Result<Self> {
        Ok(Self {
            label: label.into(),
            data: ManifestData::Binary(
                serde_cbor::to_vec(data).map_err(|_err| Error::AssertionEncoding)?,
            ),
            instance: None,
            kind: Some(ManifestAssertionKind::Cbor),
        })
    }

    pub fn from_assertion<T: Serialize + AssertionBase>(data: &T) -> Result<Self> {
        Ok(Self::new(
            data.label().to_owned(),
            serde_json::to_value(data).map_err(|_err| Error::AssertionEncoding)?,
        ))
    }

    pub fn to_assertion<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(self.value()?.to_owned()).map_err(|e| {
            Error::AssertionDecoding(AssertionDecodeError::from_json_err(
                self.label.to_owned(),
                None,
                "application/json".to_owned(),
                e,
            ))
        })
    }
}
