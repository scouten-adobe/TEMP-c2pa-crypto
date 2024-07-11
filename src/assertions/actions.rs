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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_cbor::Value;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::{labels, Actor, Metadata},
    error::Result,
    resource_store::UriOrResource,
    utils::cbor_types::DateT,
    ClaimGeneratorInfo,
};

const ASSERTION_CREATION_VERSION: usize = 2;

/// Specification defined C2PA actions
pub(crate) mod c2pa_action {
    #[allow(dead_code)]
    pub(crate) const CROPPED: &str = "c2pa.cropped";

    #[allow(dead_code)]
    pub(crate) const EDITED: &str = "c2pa.edited";
}

/// We use this to allow SourceAgent to be either a string or a
/// ClaimGeneratorInfo
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum SoftwareAgent {
    String(String),
    ClaimGeneratorInfo(ClaimGeneratorInfo),
}

impl From<&str> for SoftwareAgent {
    fn from(s: &str) -> Self {
        Self::String(s.to_owned())
    }
}

impl From<ClaimGeneratorInfo> for SoftwareAgent {
    fn from(c: ClaimGeneratorInfo) -> Self {
        Self::ClaimGeneratorInfo(c)
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Action {
    /// The label associated with this action. See ([`c2pa_action`]).
    action: String,

    /// Timestamp of when the action occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    when: Option<DateT>,

    /// The software agent that performed the action.
    #[serde(rename = "softwareAgent", skip_serializing_if = "Option::is_none")]
    software_agent: Option<SoftwareAgent>,

    /// A semicolon-delimited list of the parts of the resource that were
    /// changed since the previous event history.
    #[serde(skip_serializing_if = "Option::is_none")]
    changed: Option<String>,

    /// A list of the regions of interest of the resource that were changed.
    ///
    /// If not present, presumed to be undefined.
    /// When tracking changes and the scope of the changed components is
    /// unknown, it should be assumed that anything might have changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    changes: Option<Vec<serde_json::Value>>,

    /// The value of the `xmpMM:InstanceID` property for the modified (output)
    /// resource.
    #[serde(rename = "instanceId", skip_serializing_if = "Option::is_none")]
    instance_id: Option<String>,

    /// Additional parameters of the action. These vary by the type of action.
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<HashMap<String, Value>>,

    /// An array of the creators that undertook this action.
    #[serde(skip_serializing_if = "Option::is_none")]
    actors: Option<Vec<Actor>>,
    /// One of the defined URI values at `<https://cv.iptc.org/newscodes/digitalsourcetype/>`
    #[serde(rename = "digitalSourceType", skip_serializing_if = "Option::is_none")]
    source_type: Option<String>,

    /// List of related actions.
    #[serde(skip_serializing_if = "Option::is_none")]
    related: Option<Vec<Action>>,

    // The reason why this action was performed, required when the action is `c2pa.redacted`
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[allow(dead_code)] // some funcs still used in test
impl Action {
    pub(crate) fn new(label: &str) -> Self {
        Self {
            action: label.to_owned(),
            ..Default::default()
        }
    }

    fn is_v2(&self) -> bool {
        matches!(
            self.software_agent,
            Some(SoftwareAgent::ClaimGeneratorInfo(_))
        ) || self.changes.is_some() // only defined for v2
    }

    pub(crate) fn action(&self) -> &str {
        &self.action
    }

    pub(crate) fn when(&self) -> Option<&str> {
        self.when.as_deref()
    }

    pub(crate) fn software_agent(&self) -> Option<&SoftwareAgent> {
        self.software_agent.as_ref()
    }

    pub(crate) fn software_agent_mut(&mut self) -> Option<&mut SoftwareAgent> {
        self.software_agent.as_mut()
    }

    pub(crate) fn instance_id(&self) -> Option<&str> {
        self.instance_id.as_deref()
    }

    pub(crate) fn parameters(&self) -> Option<&HashMap<String, Value>> {
        self.parameters.as_ref()
    }

    pub(crate) fn get_parameter(&self, key: &str) -> Option<&Value> {
        match self.parameters.as_ref() {
            Some(parameters) => parameters.get(key),
            None => None,
        }
    }

    pub(crate) fn actors(&self) -> Option<&[Actor]> {
        self.actors.as_deref()
    }

    pub(crate) fn source_type(&self) -> Option<&str> {
        self.source_type.as_deref()
    }

    pub(crate) fn related(&self) -> Option<&[Action]> {
        self.related.as_deref()
    }

    pub(crate) fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    pub(crate) fn set_when<S: Into<String>>(mut self, when: S) -> Self {
        self.when = Some(DateT(when.into()));
        self
    }

    pub(crate) fn set_software_agent<S: Into<SoftwareAgent>>(mut self, software_agent: S) -> Self {
        self.software_agent = Some(software_agent.into());
        self
    }

    pub(crate) fn set_changed(mut self, changed: Option<&Vec<&str>>) -> Self {
        self.changed = changed.map(|v| v.join(";"));
        self
    }

    pub(crate) fn set_instance_id<S: Into<String>>(mut self, id: S) -> Self {
        self.instance_id = Some(id.into());
        self
    }

    pub(crate) fn set_parameter<S: Into<String>, T: Serialize>(
        mut self,
        key: S,
        value: T,
    ) -> Result<Self> {
        let value_bytes = serde_cbor::ser::to_vec(&value)?;
        let value = serde_cbor::from_slice(&value_bytes)?;

        self.parameters = Some(match self.parameters {
            Some(mut parameters) => {
                parameters.insert(key.into(), value);
                parameters
            }
            None => {
                let mut p = HashMap::new();
                p.insert(key.into(), value);
                p
            }
        });
        Ok(self)
    }

    pub(crate) fn set_actors(mut self, actors: Option<&Vec<Actor>>) -> Self {
        self.actors = actors.cloned();
        self
    }

    pub(crate) fn set_source_type<S: Into<String>>(mut self, uri: S) -> Self {
        self.source_type = Some(uri.into());
        self
    }

    pub(crate) fn set_related(mut self, related: Option<&Vec<Action>>) -> Self {
        self.related = related.cloned();
        self
    }

    pub(crate) fn set_reason<S: Into<String>>(mut self, reason: S) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

#[derive(Deserialize, Serialize, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct ActionTemplate {
    /// The label associated with this action. See ([`c2pa_action`]).
    pub(crate) action: String,

    /// The software agent that performed the action.
    #[serde(rename = "softwareAgent", skip_serializing_if = "Option::is_none")]
    pub(crate) software_agent: Option<SoftwareAgent>,

    /// One of the defined URI values at `<https://cv.iptc.org/newscodes/digitalsourcetype/>`
    #[serde(rename = "digitalSourceType", skip_serializing_if = "Option::is_none")]
    pub(crate) source_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) icon: Option<UriOrResource>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) parameters: Option<HashMap<String, Value>>,
}

#[allow(dead_code)] // some funcs still used in test
impl ActionTemplate {
    pub(crate) fn new<S: Into<String>>(action: S) -> Self {
        Self {
            action: action.into(),
            ..Default::default()
        }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct Actions {
    pub(crate) actions: Vec<Action>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) templates: Option<Vec<ActionTemplate>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) metadata: Option<Metadata>,
}

#[allow(dead_code)] // some funcs still used in test
impl Actions {
    pub(crate) const LABEL: &'static str = labels::ACTIONS;

    pub(crate) fn new() -> Self {
        Self {
            actions: Vec::new(),
            templates: None,
            metadata: None,
        }
    }

    fn is_v2(&self) -> bool {
        if self.templates.is_some() {
            return true;
        };
        self.actions.iter().any(|a| a.is_v2())
    }

    pub(crate) fn actions(&self) -> &[Action] {
        &self.actions
    }

    pub(crate) fn actions_mut(&mut self) -> &mut [Action] {
        &mut self.actions
    }

    pub(crate) fn metadata(&self) -> Option<&Metadata> {
        self.metadata.as_ref()
    }

    pub(crate) fn update_action(mut self, index: usize, action: Action) -> Self {
        self.actions[index] = action;
        self
    }

    pub(crate) fn add_action(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    pub(crate) fn add_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub(crate) fn from_json_value(json: &serde_json::Value) -> Result<Self> {
        let buf: Vec<u8> = Vec::new();
        let json_str = json.to_string();
        let mut from = serde_json::Deserializer::from_str(&json_str);
        let mut to = serde_cbor::Serializer::new(buf);

        serde_transcode::transcode(&mut from, &mut to)?;
        let buf2 = to.into_inner();

        let actions: Actions = serde_cbor::from_slice(&buf2)?;
        Ok(actions)
    }
}

impl AssertionCbor for Actions {}

impl AssertionBase for Actions {
    const LABEL: &'static str = labels::ACTIONS;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    fn version(&self) -> Option<usize> {
        if self.is_v2() {
            Some(2)
        } else {
            Some(1)
        }
    }

    fn label(&self) -> &str {
        if self.is_v2() {
            "c2pa.actions.v2"
        } else {
            labels::ACTIONS
        }
    }

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

impl Default for Actions {
    fn default() -> Self {
        Self::new()
    }
}
