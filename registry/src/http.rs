//! Range-compatible HTTP transport for the local registry.
use crate::{
    Error, MAX_BLOB_BYTES, MAX_FRAMES, MAX_LAYOUT_BYTES, MAX_LIST_BYTES, MAX_RECORD_BYTES,
    Reference, Registry, Release, Result, check_digest,
    store::{BodyRef, Layout, copy_bounded, write_download},
};
use axum::{
    Router,
    body::Body,
    extract::{Path as Route, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use http_body_util::BodyExt as _;
use reqwest::{Url, blocking};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq as _;
use tokio::{io::AsyncWriteExt, sync::Semaphore, task};
use tokio_util::io::{ReaderStream, SyncIoBridge};

const PUBLICATION_MEDIA: &str = "application/vnd.sac.registry.publication.v1+json";
const MAX_PUBLICATION_BYTES: u64 = MAX_LAYOUT_BYTES + MAX_RECORD_BYTES + 64;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    release: Release,
    layout: Layout,
}

#[derive(Clone)]
struct Server {
    registry: Registry,
    writable: bool,
    auth: Option<HeaderValue>,
    transfers: Arc<Semaphore>,
}

pub fn router(registry: Registry, writable: bool, token: Option<&str>) -> Result<Router> {
    let auth = token
        .map(|token| {
            if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
                return Err(Error::Invalid("invalid bearer token".into()));
            }
            HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| Error::Invalid("invalid bearer token".into()))
        })
        .transpose()?;
    Ok(Router::new()
        .route("/v1/releases", get(list))
        .route(
            "/v1/releases/{namespace}/{name}/{version}",
            get(resolve).put(publish),
        )
        .route("/v1/objects/missing", post(missing_bodies))
        .route("/v1/objects/{object}/{digest}", put(put_body))
        .route("/v1/archives/{digest}", get(archive))
        .with_state(Server {
            registry,
            writable,
            auth,
            transfers: Arc::new(Semaphore::new(8)),
        }))
}

impl Server {
    fn authenticate(&self, headers: &HeaderMap) -> std::result::Result<(), StatusCode> {
        if let Some(expected) = &self.auth {
            let supplied = headers
                .get(header::AUTHORIZATION)
                .map_or(&[][..], HeaderValue::as_bytes);
            if !bool::from(expected.as_bytes().ct_eq(supplied)) {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        Ok(())
    }

    fn authorize_write(&self, headers: &HeaderMap, conditional: bool) -> HttpResult<()> {
        self.authenticate(headers)?;
        if !self.writable {
            return Err(StatusCode::FORBIDDEN.into());
        }
        if conditional
            && headers
                .get(header::IF_NONE_MATCH)
                .and_then(|value| value.to_str().ok())
                != Some("*")
        {
            return Err(StatusCode::PRECONDITION_REQUIRED.into());
        }
        Ok(())
    }

    async fn permit(&self) -> HttpResult<tokio::sync::OwnedSemaphorePermit> {
        self.transfers
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into())
    }
}

type HttpResult<T> = std::result::Result<T, HttpError>;
enum HttpError {
    Status(StatusCode),
    Registry(Error),
}

impl From<Error> for HttpError {
    fn from(error: Error) -> Self {
        Self::Registry(error)
    }
}

impl From<StatusCode> for HttpError {
    fn from(status: StatusCode) -> Self {
        Self::Status(status)
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Status(status) => status,
            Self::Registry(error) => match error {
                Error::NotFound(_) => StatusCode::NOT_FOUND,
                Error::Conflict(_) => StatusCode::CONFLICT,
                Error::Limit(_) | Error::Sac(sac::Error::Limit(_)) => StatusCode::PAYLOAD_TOO_LARGE,
                Error::Invalid(_) | Error::Integrity(_) | Error::Sac(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
        };
        if status == StatusCode::UNAUTHORIZED {
            (status, [(header::WWW_AUTHENTICATE, "Bearer")]).into_response()
        } else {
            status.into_response()
        }
    }
}

fn joined<T>(result: std::result::Result<Result<T>, task::JoinError>) -> HttpResult<T> {
    result
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(HttpError::from)
}

fn json(value: &impl serde::Serialize, maximum: u64, status: StatusCode) -> HttpResult<Response> {
    let bytes = serde_json::to_vec(value).map_err(Error::from)?;
    if bytes.len() as u64 > maximum {
        return Err(Error::Limit("serialized registry response size").into());
    }
    Ok((status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogQuery {
    profile: Option<String>,
    version: Option<u32>,
    tag: Option<String>,
}

async fn list(
    State(state): State<Server>,
    headers: HeaderMap,
    Query(query): Query<CatalogQuery>,
) -> HttpResult<Response> {
    state.authenticate(&headers)?;
    if query.version.is_some() && query.profile.is_none() {
        return Err(StatusCode::BAD_REQUEST.into());
    }
    let permit = state
        .transfers
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let releases = joined(
        task::spawn_blocking(move || {
            let _permit = permit;
            state.registry.list(
                query.profile.as_deref(),
                query.version,
                query.tag.as_deref(),
            )
        })
        .await,
    )?;
    json(&releases, MAX_LIST_BYTES, StatusCode::OK)
}

async fn resolve(
    State(state): State<Server>,
    Route((namespace, name, version)): Route<(String, String, String)>,
    headers: HeaderMap,
) -> HttpResult<Response> {
    state.authenticate(&headers)?;
    let reference = Reference::new(&namespace, &name, &version)?;
    let permit = state
        .transfers
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let release = joined(
        task::spawn_blocking(move || {
            let _permit = permit;
            state.registry.resolve(&reference)
        })
        .await,
    )?;
    json(&release, MAX_RECORD_BYTES, StatusCode::OK)
}

async fn publish(
    State(state): State<Server>,
    Route((namespace, name, version)): Route<(String, String, String)>,
    headers: HeaderMap,
    mut body: Body,
) -> HttpResult<Response> {
    state.authorize_write(&headers, true)?;
    let reference = Reference::new(&namespace, &name, &version)?;
    let permit = state.permit().await?;
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        == Some(PUBLICATION_MEDIA)
    {
        let publication: Publication = read_json_body(body, MAX_PUBLICATION_BYTES).await?;
        let release = joined(
            task::spawn_blocking(move || {
                let _permit = permit;
                state.registry.publish_layout(
                    &reference,
                    &publication.release,
                    &publication.layout,
                    |object, digest, size| state.registry.read_body(object, digest, size),
                )
            })
            .await,
        )?;
        return json(&release, MAX_RECORD_BYTES, StatusCode::CREATED);
    }
    let profile = headers
        .get("sac-profile")
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .map_err(|_| StatusCode::BAD_REQUEST)
        })
        .transpose()?;
    let staging = state.registry.stage()?;
    let mut output = tokio::fs::File::from_std(staging.reopen().map_err(Error::from)?);
    let mut length = 0u64;
    while let Some(frame) = tokio::time::timeout(Duration::from_secs(30), body.frame())
        .await
        .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
    {
        let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Some(bytes) = frame.data_ref() {
            length = length
                .checked_add(bytes.len() as u64)
                .ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
            if length > state.registry.maximum() {
                return Err(StatusCode::PAYLOAD_TOO_LARGE.into());
            }
            output.write_all(bytes).await.map_err(Error::from)?;
        }
    }
    output.flush().await.map_err(Error::from)?;
    drop(output);
    let release = joined(
        task::spawn_blocking(move || {
            let _permit = permit;
            state
                .registry
                .publish_staged(&reference, profile.as_deref(), staging, None)
        })
        .await,
    )?;
    json(&release, MAX_RECORD_BYTES, StatusCode::CREATED)
}

async fn read_body(body: Body, maximum: u64) -> HttpResult<axum::body::Bytes> {
    let bytes = tokio::time::timeout(
        Duration::from_secs(30),
        axum::body::to_bytes(body, maximum as usize),
    )
    .await
    .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
    .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    Ok(bytes)
}

async fn read_json_body<T: serde::de::DeserializeOwned>(body: Body, maximum: u64) -> HttpResult<T> {
    let bytes = read_body(body, maximum).await?;
    serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST.into())
}

async fn missing_bodies(
    State(state): State<Server>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<Response> {
    state.authorize_write(&headers, false)?;
    let permit = state.permit().await?;
    let wanted: Vec<BodyRef> = read_json_body(body, MAX_LAYOUT_BYTES).await?;
    if wanted.len() > MAX_FRAMES {
        return Err(Error::Limit("frame inventory count").into());
    }
    let missing = joined(
        task::spawn_blocking(move || {
            let _permit = permit;
            let mut missing = Vec::new();
            for body in wanted {
                if !state.registry.has_body(&body)? {
                    missing.push(body);
                }
            }
            Ok(missing)
        })
        .await,
    )?;
    json(&missing, MAX_LAYOUT_BYTES, StatusCode::OK)
}

async fn put_body(
    State(state): State<Server>,
    Route((object, digest)): Route<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> HttpResult<StatusCode> {
    state.authorize_write(&headers, true)?;
    check_digest(&object)?;
    check_digest(&digest)?;
    let header = headers
        .get("sac-frame")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() == 2 * sac::v1::wire::FRAME)
        .and_then(|value| hex::decode(value).ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let permit = state.permit().await?;
    let bytes = read_body(body, MAX_BLOB_BYTES.min(state.registry.maximum())).await?;
    joined(
        task::spawn_blocking(move || {
            let _permit = permit;
            state.registry.put_body(&object, &digest, &header, &bytes)
        })
        .await,
    )?;
    Ok(StatusCode::CREATED)
}

async fn archive(
    State(state): State<Server>,
    Route(digest): Route<String>,
    method: Method,
    headers: HeaderMap,
) -> HttpResult<Response> {
    state.authenticate(&headers)?;
    check_digest(&digest)?;
    let permit = state
        .transfers
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut source = joined(task::spawn_blocking(move || state.registry.archive(&digest)).await)?;
    let artifact = source.artifact();
    let size = artifact.bytes;
    let etag = format!("\"sha256:{}\"", artifact.sha256);
    if let Some(value) = headers.get(header::IF_MATCH)
        && value.as_bytes() != etag.as_bytes()
        && value.as_bytes() != b"*"
    {
        return Err(StatusCode::PRECONDITION_FAILED.into());
    }
    if let Some(value) = headers.get(header::IF_NONE_MATCH)
        && (value.as_bytes() == etag.as_bytes() || value.as_bytes() == b"*")
    {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
    }
    let mut builder = Response::builder()
        .header(header::ETAG, etag.as_str())
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CACHE_CONTROL, "private, no-transform")
        .header(header::CONTENT_TYPE, "application/octet-stream");
    let (start, end) = match headers.get(header::RANGE).filter(|_| method == Method::GET) {
        Some(range)
            if headers
                .get(header::IF_RANGE)
                .is_none_or(|value| value.as_bytes() == etag.as_bytes()) =>
        {
            let Some((start, end)) = range
                .to_str()
                .ok()
                .and_then(|range| parse_range(range, size))
            else {
                return Ok((
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    [(header::CONTENT_RANGE, format!("bytes */{size}"))],
                )
                    .into_response());
            };
            builder = builder.status(StatusCode::PARTIAL_CONTENT).header(
                header::CONTENT_RANGE,
                format!("bytes {start}-{}/{size}", end - 1),
            );
            (start, end)
        }
        _ => (0, size),
    };
    let length = end - start;
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        source.seek(SeekFrom::Start(start)).map_err(Error::from)?;
        let (writer, reader) = tokio::io::duplex(64 << 10);
        let mut writer = SyncIoBridge::new(writer);
        task::spawn_blocking(move || {
            let _permit = permit;
            // Early closure yields an incomplete body, which clients treat as a failed transfer.
            let _ = io::copy(&mut source.take(length), &mut writer);
        });
        Body::from_stream(ReaderStream::new(reader))
    };
    builder
        .header(header::CONTENT_LENGTH, length)
        .body(body)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into())
}

fn parse_range(value: &str, size: u64) -> Option<(u64, u64)> {
    let (start, end) = value.strip_prefix("bytes=")?.split_once('-')?;
    if start.is_empty() {
        let suffix = decimal(end)?.min(size);
        return (suffix > 0).then_some((size - suffix, size));
    }
    let start = decimal(start)?;
    let end = if end.is_empty() {
        size
    } else {
        decimal(end)?.saturating_add(1).min(size)
    };
    (start < end).then_some((start, end))
}

fn decimal(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

pub(crate) struct Transport {
    pub endpoint: Url,
    client: blocking::Client,
    token: Option<String>,
}

impl Transport {
    pub fn new(endpoint: &str, token: Option<&str>) -> Result<Self> {
        let mut endpoint =
            Url::parse(endpoint).map_err(|_| Error::Invalid("invalid registry URL".into()))?;
        let loopback = endpoint.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
        if !(endpoint.scheme() == "https" || endpoint.scheme() == "http" && loopback)
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(Error::Invalid("registry URL requires HTTPS or loopback HTTP, without credentials, query, or fragment".into()));
        }
        if !endpoint.path().ends_with('/') {
            endpoint
                .path_segments_mut()
                .map_err(|_| Error::Invalid("invalid endpoint path".into()))?
                .push("");
        }
        if token.is_some_and(|token| {
            token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic())
        }) {
            return Err(Error::Invalid("invalid bearer token".into()));
        }
        let client = blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(600))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(network)?;
        Ok(Self {
            endpoint,
            client,
            token: token.map(str::to_owned),
        })
    }

    pub fn url(&self, path: &str) -> Result<Url> {
        self.endpoint
            .join(path)
            .map_err(|_| Error::Invalid("invalid registry path".into()))
    }

    pub fn request(&self, method: Method, url: Url) -> Result<blocking::RequestBuilder> {
        if url.origin() != self.endpoint.origin()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::Invalid(
                "registry request changed origin or supplied credentials".into(),
            ));
        }
        let mut request = self
            .client
            .request(method, url)
            .header(header::ACCEPT_ENCODING, "identity");
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        Ok(request)
    }
}

pub(crate) fn network(error: reqwest::Error) -> Error {
    Error::Transport(error.without_url().to_string())
}

pub(crate) fn response_bytes(response: blocking::Response, maximum: u64) -> Result<Vec<u8>> {
    if response.content_length().is_some_and(|len| len > maximum) {
        return Err(Error::Limit("transfer byte count"));
    }
    let mut data = Vec::new();
    copy_bounded(response, &mut data, maximum)?;
    Ok(data)
}

pub(crate) fn require(
    response: blocking::Response,
    status: StatusCode,
    operation: &'static str,
) -> Result<blocking::Response> {
    if response.status() == status {
        return Ok(response);
    }
    match response.status() {
        StatusCode::NOT_FOUND => Err(Error::NotFound(operation.into())),
        StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED => {
            Err(Error::Conflict(operation.into()))
        }
        StatusCode::PAYLOAD_TOO_LARGE => Err(Error::Limit("remote transfer")),
        status => Err(Error::Transport(format!(
            "{operation} returned HTTP {status}"
        ))),
    }
}

pub struct Client(Transport);

impl Client {
    pub fn new(endpoint: &str, token: Option<&str>) -> Result<Self> {
        Ok(Self(Transport::new(endpoint, token)?))
    }

    fn release_url(&self, reference: &Reference) -> Result<Url> {
        reference.key()?;
        self.0.url(&format!(
            "v1/releases/{}/{}/{}",
            reference.namespace, reference.name, reference.version
        ))
    }

    pub fn resolve(&self, reference: &Reference) -> Result<Release> {
        let response = self
            .0
            .request(Method::GET, self.release_url(reference)?)?
            .send()
            .map_err(network)?;
        decode_release(
            require(response, StatusCode::OK, "resolve release")?,
            reference,
        )
    }

    pub fn list(
        &self,
        profile: Option<&str>,
        version: Option<u32>,
        tag: Option<&str>,
    ) -> Result<Vec<Release>> {
        if version.is_some() && profile.is_none() {
            return Err(Error::Invalid("select a profile before its version".into()));
        }
        let mut url = self.0.url("v1/releases")?;
        if let Some(profile) = profile {
            url.query_pairs_mut().append_pair("profile", profile);
        }
        if let Some(version) = version {
            url.query_pairs_mut()
                .append_pair("version", &version.to_string());
        }
        if let Some(tag) = tag {
            url.query_pairs_mut().append_pair("tag", tag);
        }
        let response = self.0.request(Method::GET, url)?.send().map_err(network)?;
        let releases: Vec<Release> = serde_json::from_slice(&response_bytes(
            require(response, StatusCode::OK, "list releases")?,
            MAX_LIST_BYTES,
        )?)?;
        for release in &releases {
            release.validate()?;
            if !release.matches(profile, version, tag) {
                return Err(Error::Integrity("catalog profile filter"));
            }
        }
        Ok(releases)
    }

    pub fn publish(
        &self,
        reference: &Reference,
        profile: Option<&str>,
        file: File,
        maximum: u64,
    ) -> Result<Release> {
        if file.metadata()?.len() > maximum {
            return Err(Error::Limit("artifact length"));
        }
        let scratch = tempfile::tempdir()?;
        let local = Registry::open(scratch.path(), maximum)?;
        let release = local.publish(reference, profile, file)?;
        match self.resolve(reference) {
            Ok(existing) if existing == release => return Ok(existing),
            Ok(_) => return Err(Error::Conflict(reference.to_string())),
            Err(Error::NotFound(_)) => (),
            Err(error) => return Err(error),
        }
        let layout = local.layout(&release.artifact.sha256)?;
        let mut candidates = layout.frame_headers()?;
        let inventory: Vec<_> = candidates.keys().collect();
        // Koda probed the destination and sent only missing blobs. The batch
        // inventory preserves that behavior with one round trip for the probes.
        let response = self
            .0
            .request(Method::POST, self.0.url("v1/objects/missing")?)?
            .header(header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&inventory)?)
            .send()
            .map_err(network)?;
        let builder = self
            .0
            .request(Method::PUT, self.release_url(reference)?)?
            .header(header::IF_NONE_MATCH, "*");
        let response = match response.status() {
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED => {
                let mut request = builder.header(header::CONTENT_TYPE, "application/octet-stream");
                if let Some(profile) = profile {
                    request = request.header("sac-profile", profile);
                }
                request
                    .body(blocking::Body::sized(
                        local.archive(&release.artifact.sha256)?,
                        release.artifact.bytes,
                    ))
                    .send()
                    .map_err(network)?
            }
            _ => {
                let missing: Vec<BodyRef> = serde_json::from_slice(&response_bytes(
                    require(response, StatusCode::OK, "probe frame inventory")?,
                    MAX_LAYOUT_BYTES,
                )?)?;
                for body in missing {
                    let header = candidates
                        .remove(&body)
                        .ok_or(Error::Integrity("missing frame inventory result"))?;
                    let url = self
                        .0
                        .url(&format!("v1/objects/{}/{}", body.object, body.sha256))?;
                    let response = self
                        .0
                        .request(Method::PUT, url)?
                        .header(header::IF_NONE_MATCH, "*")
                        .header("sac-frame", header)
                        .body(local.read_body(&body.object, &body.sha256, body.bytes)?)
                        .send()
                        .map_err(network)?;
                    require(response, StatusCode::CREATED, "publish frame body")?;
                }
                builder
                    .header(header::CONTENT_TYPE, PUBLICATION_MEDIA)
                    .body(serde_json::to_vec(&Publication {
                        release: release.clone(),
                        layout,
                    })?)
                    .send()
                    .map_err(network)?
            }
        };
        let published = decode_release(
            require(response, StatusCode::CREATED, "publish release")?,
            reference,
        )?;
        if published != release {
            return Err(Error::Integrity("published release binding"));
        }
        Ok(published)
    }

    pub fn fetch(
        &self,
        reference: &Reference,
        output: &Path,
        maximum: u64,
        expected_digest: Option<&str>,
    ) -> Result<Release> {
        let release = self.resolve(reference)?;
        if release.artifact.bytes > maximum {
            return Err(Error::Limit("artifact length"));
        }
        if expected_digest.is_some_and(|digest| digest != release.artifact.sha256) {
            return Err(Error::Integrity("release digest pin"));
        }
        let url = self
            .0
            .url(&format!("v1/archives/{}", release.artifact.sha256))?;
        let response = self.0.request(Method::GET, url)?.send().map_err(network)?;
        write_download(
            require(response, StatusCode::OK, "fetch archive")?,
            &release.artifact,
            output,
        )?;
        Ok(release)
    }
}

fn decode_release(response: blocking::Response, reference: &Reference) -> Result<Release> {
    let release: Release = serde_json::from_slice(&response_bytes(response, MAX_RECORD_BYTES)?)?;
    if release.validate()? != *reference {
        return Err(Error::Integrity("release binding"));
    }
    Ok(release)
}
