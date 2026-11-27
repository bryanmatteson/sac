use serde::{Deserialize, Serialize};

use super::{CONFIG_MEDIA, MANIFEST_MEDIA};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OciDescriptor {
    pub(crate) media_type: String,
    pub(crate) digest: String,
    pub(crate) size: u64,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub(crate) annotations: std::collections::BTreeMap<String, String>,
}

impl OciDescriptor {
    pub(crate) fn new(
        media_type: impl Into<String>,
        digest: impl Into<String>,
        size: usize,
    ) -> Self {
        Self {
            media_type: media_type.into(),
            digest: digest.into(),
            size: size as u64,
            annotations: std::collections::BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OciManifest {
    pub(crate) schema_version: u32,
    pub(crate) media_type: String,
    pub(crate) artifact_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) subject: Option<OciDescriptor>,
    pub(crate) config: OciDescriptor,
    pub(crate) layers: Vec<OciDescriptor>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub(crate) annotations: std::collections::BTreeMap<String, String>,
}

impl OciManifest {
    pub(crate) fn new(
        artifact_type: impl Into<String>,
        config_digest: impl Into<String>,
        layers: Vec<OciDescriptor>,
    ) -> Self {
        Self {
            schema_version: 2,
            media_type: MANIFEST_MEDIA.into(),
            artifact_type: artifact_type.into(),
            subject: None,
            config: OciDescriptor::new(CONFIG_MEDIA, config_digest, 2),
            layers,
            annotations: std::collections::BTreeMap::new(),
        }
    }
}
