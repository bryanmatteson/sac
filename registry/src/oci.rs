//! OCI distribution using one layout and independently addressed frame bodies.
#[path = "oci_model.rs"]
mod model;

use crate::{
    Error, MAX_BLOB_BYTES, MAX_LAYOUT_BYTES, MAX_RECORD_BYTES, Reference, Registry, Release,
    Result, check_digest,
    http::{Transport, network, require, response_bytes},
    sha256,
    store::Layout,
};
use model::{OciDescriptor, OciManifest};
use reqwest::{Method, StatusCode, header};
use std::{collections::BTreeMap, sync::Mutex};

const MANIFEST_MEDIA: &str = "application/vnd.oci.image.manifest.v1+json";
const CONFIG_MEDIA: &str = "application/vnd.oci.empty.v1+json";
const RELEASE_MEDIA: &str = "application/vnd.sac.registry.release.v1+json";
const LAYOUT_MEDIA: &str = "application/vnd.sac.registry.layout.v1+json";
const BLOB_MEDIA: &str = "application/vnd.sac.registry.frame-body.v1";
const ARTIFACT: &str = "application/vnd.sac.registry.archive.v1";
const PROBE: &str = "sac-registry-create-only-v1";
const PROBE_MEDIA: &str = "application/vnd.sac.registry.create-only-probe.v1";
const MAX_MANIFEST_BYTES: u64 = 4 << 20;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Naming {
    #[default]
    PreferName,
    RequireName,
    DigestOnly,
}

#[derive(Debug, serde::Serialize)]
pub struct Publication {
    #[serde(flatten)]
    pub release: Release,
    pub manifest_digest: String,
    pub named: bool,
}

pub struct Client {
    transport: Transport,
    repository: String,
    create_only: Mutex<Option<bool>>,
}

impl Client {
    pub fn new(locator: &str, token: Option<&str>) -> Result<Self> {
        let address = if let Some(suffix) = locator.strip_prefix("oci://") {
            format!("https://{suffix}")
        } else if let Some(suffix) = locator.strip_prefix("oci+http://") {
            format!("http://{suffix}")
        } else {
            return Err(Error::Invalid("expected oci://HOST/REPOSITORY".into()));
        };
        let mut url =
            reqwest::Url::parse(&address).map_err(|_| Error::Invalid("invalid OCI URL".into()))?;
        let repository = url
            .path()
            .strip_prefix('/')
            .unwrap_or("")
            .trim_end_matches('/')
            .to_owned();
        if repository.is_empty()
            || repository.len() > 255
            || !repository.split('/').all(repository_part)
        {
            return Err(Error::Invalid("invalid OCI repository name".into()));
        }
        url.set_path("/");
        Ok(Self {
            transport: Transport::new(url.as_str(), token)?,
            repository,
            create_only: Mutex::new(None),
        })
    }

    pub fn push(&self, registry: &Registry, reference: &Reference) -> Result<Publication> {
        self.push_with_naming(registry, reference, Naming::PreferName)
    }

    pub fn push_with_naming(
        &self,
        registry: &Registry,
        reference: &Reference,
        naming: Naming,
    ) -> Result<Publication> {
        let release = registry.resolve(reference)?;
        let tag = release_tag(reference)?;
        let layout = registry.layout(&release.artifact.sha256)?;
        let layout_bytes = serde_json::to_vec(&layout)?;
        let release_bytes = serde_json::to_vec(&release)?;
        let blobs = unique_blobs(&layout)?;
        let mut layers = vec![
            descriptor(RELEASE_MEDIA, &release_bytes),
            descriptor(LAYOUT_MEDIA, &layout_bytes),
        ];
        for (digest, (_, size)) in &blobs {
            layers.push(blob_descriptor(digest, *size));
        }
        let manifest = OciManifest::new(ARTIFACT, oci_digest(b"{}"), layers);
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        if manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(Error::Limit("OCI manifest size"));
        }

        let manifest_digest = oci_digest(&manifest_bytes);
        let named = if naming == Naming::DigestOnly {
            false
        } else {
            match self.get_manifest(&tag) {
                Ok(existing) if existing != manifest_bytes => {
                    return Err(Error::Conflict(reference.to_string()));
                }
                Ok(_) | Err(Error::NotFound(_)) => (),
                Err(error) => return Err(error),
            }
            let named = self.supports_create_only()?;
            if !named && naming == Naming::RequireName {
                return Err(Error::Invalid(
                    "OCI named releases require conditional manifest creation".into(),
                ));
            }
            named
        };
        let locator = if named { &tag } else { &manifest_digest };
        match self.get_manifest(locator) {
            Ok(existing) if existing == manifest_bytes => {
                return Ok(Publication {
                    release,
                    manifest_digest,
                    named,
                });
            }
            Ok(_) => return Err(Error::Conflict(reference.to_string())),
            Err(Error::NotFound(_)) => (),
            Err(error) => return Err(error),
        }

        // Koda published dependency blobs first and its tree manifest last.
        for data in [&b"{}"[..], &release_bytes, &layout_bytes] {
            self.put_blob(&oci_digest(data), data.to_vec())?;
        }
        for (digest, (object, size)) in blobs {
            let digest_name = format!("sha256:{digest}");
            if !self.has_blob(&digest_name)? {
                self.upload_blob(&digest_name, registry.read_body(object, digest, size)?)?;
            }
        }
        match self.put_manifest(locator, manifest_bytes.clone(), named)? {
            StatusCode::CREATED | StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED => {
                if self.get_manifest(locator)? == manifest_bytes {
                    Ok(Publication {
                        release,
                        manifest_digest,
                        named,
                    })
                } else {
                    Err(Error::Conflict(reference.to_string()))
                }
            }
            status => Err(Error::Transport(format!(
                "OCI publish manifest returned HTTP {status}"
            ))),
        }
    }

    pub fn pull(
        &self,
        registry: &Registry,
        reference: &Reference,
        expected_sha256: Option<&str>,
    ) -> Result<Release> {
        self.pull_manifest(registry, reference, None, expected_sha256)
    }

    pub fn pull_manifest(
        &self,
        registry: &Registry,
        reference: &Reference,
        manifest_digest: Option<&str>,
        expected_sha256: Option<&str>,
    ) -> Result<Release> {
        let locator = match manifest_digest {
            Some(digest) => {
                check_digest(digest.strip_prefix("sha256:").ok_or(Error::Invalid(
                    "expected sha256:HEX OCI manifest digest".into(),
                ))?)?;
                digest.to_owned()
            }
            None => release_tag(reference)?,
        };
        let json = self.get_manifest(&locator)?;
        if manifest_digest.is_some_and(|digest| oci_digest(&json) != digest) {
            return Err(Error::Integrity("OCI manifest digest"));
        }
        let manifest: OciManifest = serde_json::from_slice(&json)?;
        let [release_desc, layout_desc, rest @ ..] = manifest.layers.as_slice() else {
            return Err(Error::Integrity("OCI release layers"));
        };
        if manifest.schema_version != 2
            || manifest.media_type != MANIFEST_MEDIA
            || manifest.artifact_type != ARTIFACT
            || manifest.config != descriptor(CONFIG_MEDIA, b"{}")
            || manifest.subject.is_some()
            || release_desc.media_type != RELEASE_MEDIA
            || layout_desc.media_type != LAYOUT_MEDIA
        {
            return Err(Error::Integrity("OCI SAC artifact manifest"));
        }
        let release: Release =
            serde_json::from_slice(&self.get_blob(release_desc, MAX_RECORD_BYTES)?)?;
        if release.validate()? != *reference
            || expected_sha256.is_some_and(|value| value != release.artifact.sha256)
        {
            return Err(Error::Integrity("OCI release binding"));
        }
        if release.artifact.bytes > registry.maximum() {
            return Err(Error::Limit("artifact length"));
        }
        let layout: Layout =
            serde_json::from_slice(&self.get_blob(layout_desc, MAX_LAYOUT_BYTES)?)?;
        layout.validate(registry.maximum())?;
        if release.artifact != layout.artifact {
            return Err(Error::Integrity("OCI layout binding"));
        }
        let expected = unique_blobs(&layout)?;
        if expected.len() != rest.len()
            || rest
                .iter()
                .zip(expected.iter())
                .any(|(desc, (digest, (_, bytes)))| *desc != blob_descriptor(digest, *bytes))
        {
            return Err(Error::Integrity("OCI frame descriptors"));
        }

        registry.publish_layout(
            reference,
            &release,
            &layout,
            |object, digest, bytes| match registry.read_body(object, digest, bytes) {
                Err(Error::NotFound(_)) => {
                    self.get_blob(&blob_descriptor(digest, bytes), MAX_BLOB_BYTES)
                }
                result => result,
            },
        )
    }

    fn url(&self, path: &str) -> Result<reqwest::Url> {
        self.transport
            .url(&format!("v2/{}/{path}", self.repository))
    }

    fn get_manifest(&self, tag: &str) -> Result<Vec<u8>> {
        let response = self
            .transport
            .request(Method::GET, self.url(&format!("manifests/{tag}"))?)?
            .header(header::ACCEPT, MANIFEST_MEDIA)
            .send()
            .map_err(network)?;
        response_bytes(
            require(response, StatusCode::OK, "OCI get manifest")?,
            MAX_MANIFEST_BYTES,
        )
    }

    fn put_manifest(&self, locator: &str, bytes: Vec<u8>, conditional: bool) -> Result<StatusCode> {
        let mut request = self
            .transport
            .request(Method::PUT, self.url(&format!("manifests/{locator}"))?)?
            .header(header::CONTENT_TYPE, MANIFEST_MEDIA);
        if conditional {
            request = request.header(header::IF_NONE_MATCH, "*");
        }
        Ok(request.body(bytes).send().map_err(network)?.status())
    }

    fn get_blob(&self, descriptor: &OciDescriptor, maximum: u64) -> Result<Vec<u8>> {
        let digest = descriptor
            .digest
            .strip_prefix("sha256:")
            .ok_or(Error::Integrity("OCI blob digest algorithm"))?;
        check_digest(digest)?;
        if descriptor.size > maximum {
            return Err(Error::Limit("OCI blob size"));
        }
        let response = self
            .transport
            .request(
                Method::GET,
                self.url(&format!("blobs/{}", descriptor.digest))?,
            )?
            .send()
            .map_err(network)?;
        let data = response_bytes(
            require(response, StatusCode::OK, "OCI get blob")?,
            descriptor.size,
        )?;
        if data.len() as u64 != descriptor.size || sha256(&data) != digest {
            return Err(Error::Integrity("OCI descriptor digest or length"));
        }
        Ok(data)
    }

    fn has_blob(&self, digest: &str) -> Result<bool> {
        let response = self
            .transport
            .request(Method::HEAD, self.url(&format!("blobs/{digest}"))?)?
            .send()
            .map_err(network)?;
        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            status => Err(Error::Transport(format!(
                "OCI blob HEAD returned HTTP {status}"
            ))),
        }
    }

    fn put_blob(&self, digest: &str, bytes: Vec<u8>) -> Result<()> {
        if self.has_blob(digest)? {
            return Ok(());
        }
        self.upload_blob(digest, bytes)
    }

    fn upload_blob(&self, digest: &str, bytes: Vec<u8>) -> Result<()> {
        let start = self.url("blobs/uploads/")?;
        let response = self
            .transport
            .request(Method::POST, start.clone())?
            .send()
            .map_err(network)?;
        let response = require(response, StatusCode::ACCEPTED, "OCI start upload")?;
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(Error::Integrity("missing OCI upload location"))?;
        let mut upload = start
            .join(location)
            .map_err(|_| Error::Integrity("invalid OCI upload location"))?;
        if upload.query_pairs().any(|(key, _)| key == "digest") {
            return Err(Error::Integrity(
                "OCI upload location already supplied a digest",
            ));
        }
        upload.query_pairs_mut().append_pair("digest", digest);
        let response = self
            .transport
            .request(Method::PUT, upload)?
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(bytes)
            .send()
            .map_err(network)?;
        require(response, StatusCode::CREATED, "OCI complete upload")?;
        Ok(())
    }

    fn supports_create_only(&self) -> Result<bool> {
        let mut result = self
            .create_only
            .lock()
            .map_err(|_| Error::Integrity("OCI client lock"))?;
        if let Some(supported) = *result {
            return Ok(supported);
        }
        // Adapted from Koda's retained conditional manifest-write probe.
        let first = b"sac.registry.oci-create-only/v1 first";
        let second = b"sac.registry.oci-create-only/v1 second";
        for data in [&b"{}"[..], first.as_slice(), second.as_slice()] {
            self.put_blob(&oci_digest(data), data.to_vec())?;
        }
        let make = |data| {
            serde_json::to_vec(&OciManifest::new(
                PROBE_MEDIA,
                oci_digest(b"{}"),
                vec![descriptor(PROBE_MEDIA, data)],
            ))
        };
        let first = make(first)?;
        let second = make(second)?;
        match self.put_manifest(PROBE, first.clone(), true)? {
            StatusCode::CREATED | StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED => (),
            status => {
                return Err(Error::Transport(format!(
                    "OCI conditional-write probe returned HTTP {status}"
                )));
            }
        }
        let baseline = self.get_manifest(PROBE)?;
        let candidate = if baseline == first {
            second
        } else if baseline == second {
            first
        } else {
            return Err(Error::Conflict(
                "reserved OCI conditional-write probe".into(),
            ));
        };
        let status = self.put_manifest(PROBE, candidate, true)?;
        let supported = match status {
            StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED => {
                self.get_manifest(PROBE)? == baseline
            }
            status if status.is_success() => false,
            status => {
                return Err(Error::Transport(format!(
                    "OCI conditional-write probe returned HTTP {status}"
                )));
            }
        };
        *result = Some(supported);
        Ok(supported)
    }
}

fn repository_part(value: &str) -> bool {
    fn base(byte: u8) -> bool {
        byte.is_ascii_lowercase() || byte.is_ascii_digit()
    }
    let mut rest = value.as_bytes();
    if rest.first().is_none_or(|byte| !base(*byte)) {
        return false;
    }
    loop {
        let Some(split) = rest.iter().position(|byte| !base(*byte)) else {
            return true;
        };
        let separator = rest[split];
        let count = rest[split..]
            .iter()
            .take_while(|byte| **byte == separator)
            .count();
        if !(separator == b'-'
            || separator == b'_' && count <= 2
            || separator == b'.' && count == 1)
        {
            return false;
        }
        rest = &rest[split + count..];
        if rest.first().is_none_or(|byte| !base(*byte)) {
            return false;
        }
    }
}

fn release_tag(reference: &Reference) -> Result<String> {
    Ok(format!("sac-release-{}", reference.key()?))
}

fn oci_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256(bytes))
}

fn descriptor(media: &str, bytes: &[u8]) -> OciDescriptor {
    OciDescriptor::new(media, oci_digest(bytes), bytes.len())
}

fn blob_descriptor(digest: &str, size: u64) -> OciDescriptor {
    OciDescriptor::new(BLOB_MEDIA, format!("sha256:{digest}"), size as usize)
}

fn unique_blobs(layout: &Layout) -> Result<BTreeMap<&str, (&str, u64)>> {
    let mut selected = BTreeMap::new();
    for (object, digest, size) in layout.blobs() {
        if let Some(previous) = selected.insert(digest, (object, size))
            && previous != (object, size)
        {
            return Err(Error::Integrity("inconsistent frame body address"));
        }
    }
    Ok(selected)
}
