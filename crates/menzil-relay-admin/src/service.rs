//! The RPCs. Every handler runs the library call on a blocking thread, under a deadline, a global
//! limit on concurrent RPCs and, for changes, one mutex so that file edits are never interleaved
//! in this process (the library also takes `lock_relay`, which serializes against the CLI).
//!
//! Status messages are fixed texts: never a file system path, token text or key material. Library
//! errors are classified, and a text of theirs is passed on only when it holds nothing of the kind
//! (see [`scrub`]).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use menzil_cli::home::{Home, parse_hex32};
use menzil_cli::relay_cmd::tenants::{self, TenantError, TenantInfo, UpdateTenant};
use menzil_cli::token::decode_roster;
use menzil_proto::NetworkId;
use menzil_relay::{Class, Figures, Slug, SlugError};
use tokio::sync::Semaphore;
use tonic::{Request, Response, Status};

use crate::pb::tenant_admin_server::TenantAdmin;
use crate::pb::{
    AddNetworkRequest, CreateTenantRequest, Figure, GetFiguresRequest, GetFiguresResponse,
    ListTenantsRequest, ListTenantsResponse, RemoveNetworkRequest, RemoveTenantResponse, Tenant,
    TenantRef, UpdateTenantRequest, Usage,
};

/// The most a request message may take to decode.
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;
/// The most a roster token may take (a Roster is far smaller).
pub const MAX_TOKEN: usize = 64 * 1024;
/// How long one RPC may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// How many RPCs run at once.
pub const MAX_CONCURRENT: usize = 32;
/// `ListTenants` page sizes.
pub const DEFAULT_PAGE: usize = 100;
/// The largest page.
pub const MAX_PAGE: usize = 500;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The agent: a relay home, the mutex for changes and the limit on concurrent RPCs.
#[derive(Clone)]
pub struct Admin {
    home: Arc<Home>,
    writes: Arc<std::sync::Mutex<()>>,
    permits: Arc<Semaphore>,
}

/// Sets the flag when dropped before `disarm`: the RPC's future was dropped (deadline, client gone)
/// and a queued change must not run later.
struct CancelOnDrop {
    flag: Arc<AtomicBool>,
    armed: bool,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.flag.store(true, Ordering::SeqCst);
        }
    }
}

impl Admin {
    /// An agent for the relay home at `home`.
    pub fn new(home: Home) -> Self {
        Self {
            home: Arc::new(home),
            writes: Arc::new(std::sync::Mutex::new(())),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT)),
        }
    }

    /// Holds the mutex that every change takes, for as long as the guard lives. For tests of the
    /// serialization of changes.
    #[doc(hidden)]
    pub fn hold_writes(&self) -> std::sync::MutexGuard<'_, ()> {
        self.writes.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The generated server wrapping this agent, with the decode limit set.
    pub fn into_server(self) -> crate::pb::tenant_admin_server::TenantAdminServer<Self> {
        crate::pb::tenant_admin_server::TenantAdminServer::new(self)
            .max_decoding_message_size(MAX_MESSAGE)
            .max_encoding_message_size(MAX_MESSAGE)
    }

    /// Runs `work` on a blocking thread under the limits. `write` takes the mutex for changes.
    /// Logs the RPC name, the slug and the code, nothing else.
    async fn run<T, F>(
        &self,
        rpc: &'static str,
        slug: &str,
        write: bool,
        work: F,
    ) -> Result<T, Status>
    where
        T: Send + 'static,
        F: FnOnce(&Home) -> Result<T, Status> + Send + 'static,
    {
        let Ok(_permit) = self.permits.clone().try_acquire_owned() else {
            tracing::warn!(rpc, slug, "too many concurrent requests");
            return Err(Status::resource_exhausted("too many requests at once"));
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut guard = CancelOnDrop {
            flag: cancelled.clone(),
            armed: true,
        };
        let home = self.home.clone();
        let writes = self.writes.clone();
        let task = tokio::task::spawn_blocking(move || {
            let _held = write.then(|| writes.lock().unwrap_or_else(|e| e.into_inner()));
            if cancelled.load(Ordering::SeqCst) {
                return Err(Status::cancelled("the request was abandoned"));
            }
            work(&home)
        });
        let result = match tokio::time::timeout(REQUEST_TIMEOUT, task).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(Status::internal("internal error")),
            Err(_) => Err(Status::deadline_exceeded("the request took too long")),
        };
        guard.armed = false;
        match &result {
            Ok(_) => tracing::info!(rpc, slug, "ok"),
            Err(status) => tracing::info!(rpc, slug, code = ?status.code(), "refused"),
        }
        result
    }
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// `message` when it can be shown: no path separator, no token prefix, nothing of the home.
/// Otherwise `fallback`.
fn scrub(message: &str, home: &Home, fallback: &str) -> String {
    let root = home.root().to_string_lossy();
    if message.contains('/')
        || message.contains('\\')
        || message.contains(".toml")
        || message.contains(".roster")
        || message.contains("menzil1-")
        || (!root.is_empty() && message.contains(root.as_ref()))
        || message.len() > 300
    {
        fallback.to_string()
    } else {
        message.to_string()
    }
}

/// The gRPC status of a library error.
pub fn status_of(error: &TenantError, home: &Home) -> Status {
    match error {
        TenantError::NotFound => Status::not_found("no such tenant"),
        TenantError::AlreadyExists => {
            Status::already_exists("a tenant with this name exists already")
        }
        TenantError::Invalid(why) => {
            Status::invalid_argument(scrub(why, home, "the request is not valid"))
        }
        TenantError::Precondition(why) => Status::failed_precondition(scrub(
            why,
            home,
            "the tenant's file cannot be used or changed: repair it first",
        )),
        TenantError::Io(_) => Status::internal("the relay's files could not be read or written"),
    }
}

/// Classifies the text error of a command that has no typed error (`add_network_to`,
/// `remove_network`, `remove_tenant`) by what it says, into a fixed status. Anything unknown is
/// INTERNAL: the text is never passed on, it can hold a path.
fn status_of_command(error: &anyhow::Error) -> Status {
    let text = format!("{error:#}");
    let has = |needle: &str| text.contains(needle);
    if has("belonged to a tenant that was removed") {
        Status::failed_precondition(
            "the tenant name belonged to a removed tenant and is in quarantine",
        )
    } else if has("is already in tenant") {
        Status::failed_precondition("the network is in another tenant: remove it there first")
    } else if has("is listed by a tenant file that is not used") {
        Status::failed_precondition(
            "a tenant file that lists the network is not used: repair it first",
        )
    } else if has("is suspended") {
        Status::failed_precondition("the tenant is suspended: resume it first")
    } else if has("cannot take it") || has("would take tenant") {
        Status::failed_precondition("the relay would refuse the tenant with this network")
    } else if has("network(s) (its class's figure)") {
        Status::failed_precondition("the tenant has the most networks its class allows")
    } else if has("has expired") {
        Status::invalid_argument("the roster token has expired: ask the owner for a current one")
    } else if has("is not acceptable") {
        Status::invalid_argument("the roster token is not acceptable")
    } else if has("has no tenant") || has("does not serve network") {
        Status::not_found("no such tenant or network")
    } else {
        Status::internal("the relay's files could not be read or written")
    }
}

fn parse_slug(text: &str) -> Result<Slug, Status> {
    Slug::parse(text).map_err(|e| match e {
        SlugError::Reserved(_) => Status::failed_precondition("this tenant name is reserved"),
        _ => Status::invalid_argument(
            "the tenant name is not valid: 3 to 32 lowercase letters, digits or hyphens",
        ),
    })
}

fn check_token(token: &str) -> Result<NetworkId, Status> {
    if token.is_empty() {
        return Err(Status::invalid_argument("a roster token is required"));
    }
    if token.len() > MAX_TOKEN {
        return Err(Status::invalid_argument("the roster token is too large"));
    }
    let (roster, _) = decode_roster(token)
        .map_err(|_| Status::invalid_argument("the roster token cannot be read"))?;
    let body = roster
        .decode()
        .map_err(|_| Status::invalid_argument("the roster token cannot be read"))?;
    Ok(body.network_id)
}

fn tenant_pb(info: &TenantInfo) -> Tenant {
    Tenant {
        slug: info.slug.clone(),
        network_ids: info.network_ids.iter().map(NetworkId::to_hex).collect(),
        class: info.class.as_str().to_string(),
        terminated: info.terminated,
        suspended: info.suspended,
        added_unix: i64::try_from(info.added_unix).unwrap_or(i64::MAX),
        quota_overrides: info.quota_overrides.clone().into_iter().collect(),
    }
}

fn lib<T>(home: &Home, result: Result<T, TenantError>) -> Result<T, Status> {
    result.map_err(|e| status_of(&e, home))
}

fn command<T>(result: anyhow::Result<T>) -> Result<T, Status> {
    result.map_err(|e| status_of_command(&e))
}

/// The friend class defaults by key, read from the `Debug` form of [`Figures::friend`] so that a
/// key added to `Figures` shows up without a change here (a test covers every key).
fn friend_defaults() -> BTreeMap<String, u64> {
    let text = format!("{:?}", Figures::friend());
    let inner = text
        .split_once('{')
        .and_then(|(_, rest)| rest.rsplit_once('}'))
        .map_or("", |(inside, _)| inside);
    inner
        .split(',')
        .filter_map(|part| {
            let (key, value) = part.split_once(':')?;
            Some((key.trim().to_string(), value.trim().parse().ok()?))
        })
        .collect()
}

/// The figures a tenant may carry, for `GetFigures`.
pub fn figures() -> Vec<Figure> {
    let defaults = friend_defaults();
    Figures::KEYS
        .iter()
        .map(|&(key, max)| Figure {
            key: key.to_string(),
            class_default_friend: defaults.get(key).copied().unwrap_or(0),
            class_default_personal: 0,
            max,
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// The service
// ---------------------------------------------------------------------------------------------

#[tonic::async_trait]
impl TenantAdmin for Admin {
    async fn create_tenant(
        &self,
        request: Request<CreateTenantRequest>,
    ) -> Result<Response<Tenant>, Status> {
        let req = request.into_inner();
        let slug_text = req.slug.clone();
        self.run("CreateTenant", &slug_text, true, move |home| {
            let slug = parse_slug(&req.slug)?;
            let class = match req.class.as_str() {
                "" | "friend" => Class::Friend,
                "personal" => Class::Personal,
                _ => return Err(Status::invalid_argument("class is `personal` or `friend`")),
            };
            if req.tokens.len() != 1 {
                return Err(Status::invalid_argument(
                    "exactly one roster token is required",
                ));
            }
            let network = check_token(&req.tokens[0])?;
            match tenants::get_tenant(home, slug.as_str()) {
                Ok(existing) => {
                    // Same slug and the same networks: a repeat of the call, success (the newer
                    // token renews). Other networks: the name is taken.
                    if existing.network_ids != [network] {
                        return Err(Status::already_exists(
                            "a tenant with this name and other networks exists already",
                        ));
                    }
                    command(tenants::add_network_to(
                        home,
                        &req.tokens[0],
                        now(),
                        Some(slug.as_str()),
                    ))?;
                }
                Err(TenantError::NotFound) => {
                    command(tenants::add_network_to(
                        home,
                        &req.tokens[0],
                        now(),
                        Some(slug.as_str()),
                    ))?;
                    if class == Class::Personal {
                        lib(
                            home,
                            tenants::update_tenant(
                                home,
                                slug.as_str(),
                                UpdateTenant {
                                    class: Some(class),
                                    ..UpdateTenant::default()
                                },
                            ),
                        )?;
                    }
                }
                Err(other) => return Err(status_of(&other, home)),
            }
            let info = lib(home, tenants::get_tenant(home, slug.as_str()))?;
            Ok(Response::new(tenant_pb(&info)))
        })
        .await
    }

    async fn add_network(
        &self,
        request: Request<AddNetworkRequest>,
    ) -> Result<Response<Tenant>, Status> {
        let req = request.into_inner();
        let slug_text = req.slug.clone();
        self.run("AddNetwork", &slug_text, true, move |home| {
            let slug = parse_slug(&req.slug)?;
            check_token(&req.token)?;
            // A tenant is made by CreateTenant only.
            lib(home, tenants::get_tenant(home, slug.as_str()))?;
            command(tenants::add_network_to(
                home,
                &req.token,
                now(),
                Some(slug.as_str()),
            ))?;
            let info = lib(home, tenants::get_tenant(home, slug.as_str()))?;
            Ok(Response::new(tenant_pb(&info)))
        })
        .await
    }

    async fn remove_network(
        &self,
        request: Request<RemoveNetworkRequest>,
    ) -> Result<Response<Tenant>, Status> {
        let req = request.into_inner();
        let slug_text = req.slug.clone();
        self.run("RemoveNetwork", &slug_text, true, move |home| {
            let slug = parse_slug(&req.slug)?;
            let id = parse_hex32(req.network_id.trim())
                .map(NetworkId::from)
                .ok_or_else(|| Status::invalid_argument("network_id is 64 hex digits"))?;
            let info = lib(home, tenants::get_tenant(home, slug.as_str()))?;
            if !info.network_ids.contains(&id) {
                return Err(Status::not_found("the tenant does not list this network"));
            }
            command(tenants::remove_network(home, &id.to_hex()))?;
            let info = lib(home, tenants::get_tenant(home, slug.as_str()))?;
            Ok(Response::new(tenant_pb(&info)))
        })
        .await
    }

    async fn update_tenant(
        &self,
        request: Request<UpdateTenantRequest>,
    ) -> Result<Response<Tenant>, Status> {
        let req = request.into_inner();
        let slug_text = req.slug.clone();
        self.run("UpdateTenant", &slug_text, true, move |home| {
            let slug = parse_slug(&req.slug)?;
            let class =
                match req.class.as_deref() {
                    None => None,
                    Some(text) => Some(Class::parse(text).ok_or_else(|| {
                        Status::invalid_argument("class is `personal` or `friend`")
                    })?),
                };
            if !req.replace_quota_overrides && !req.quota_overrides.is_empty() {
                return Err(Status::invalid_argument(
                    "quota_overrides are applied only with replace_quota_overrides",
                ));
            }
            let quota_overrides = req
                .replace_quota_overrides
                .then(|| req.quota_overrides.clone().into_iter().collect());
            let info = lib(
                home,
                tenants::update_tenant(
                    home,
                    slug.as_str(),
                    UpdateTenant {
                        class,
                        terminated: req.terminated,
                        quota_overrides,
                    },
                ),
            )?;
            Ok(Response::new(tenant_pb(&info)))
        })
        .await
    }

    async fn suspend_tenant(
        &self,
        request: Request<TenantRef>,
    ) -> Result<Response<Tenant>, Status> {
        self.set_suspended("SuspendTenant", request.into_inner(), true)
            .await
    }

    async fn resume_tenant(&self, request: Request<TenantRef>) -> Result<Response<Tenant>, Status> {
        self.set_suspended("ResumeTenant", request.into_inner(), false)
            .await
    }

    async fn remove_tenant(
        &self,
        request: Request<TenantRef>,
    ) -> Result<Response<RemoveTenantResponse>, Status> {
        let req = request.into_inner();
        let slug_text = req.slug.clone();
        self.run("RemoveTenant", &slug_text, true, move |home| {
            let slug = parse_slug(&req.slug)?;
            match tenants::get_tenant(home, slug.as_str()) {
                Err(TenantError::NotFound) => {
                    return Ok(Response::new(RemoveTenantResponse { existed: false }));
                }
                // A file the relay does not use is still a tenant file to remove.
                Ok(_) | Err(TenantError::Precondition(_)) => {}
                Err(other) => return Err(status_of(&other, home)),
            }
            command(tenants::remove_tenant(home, slug.as_str(), now()))?;
            Ok(Response::new(RemoveTenantResponse { existed: true }))
        })
        .await
    }

    async fn get_tenant(&self, request: Request<TenantRef>) -> Result<Response<Tenant>, Status> {
        let req = request.into_inner();
        let slug_text = req.slug.clone();
        self.run("GetTenant", &slug_text, false, move |home| {
            let slug = parse_slug(&req.slug)?;
            let info = lib(home, tenants::get_tenant(home, slug.as_str()))?;
            Ok(Response::new(tenant_pb(&info)))
        })
        .await
    }

    async fn list_tenants(
        &self,
        request: Request<ListTenantsRequest>,
    ) -> Result<Response<ListTenantsResponse>, Status> {
        let req = request.into_inner();
        self.run("ListTenants", "", false, move |home| {
            let size = match req.page_size as usize {
                0 => DEFAULT_PAGE,
                n => n.min(MAX_PAGE),
            };
            let mut all = lib(home, tenants::list_tenants(home))?;
            all.sort_by(|a, b| a.slug.cmp(&b.slug));
            let rest: Vec<&TenantInfo> = all
                .iter()
                .filter(|t| req.page_token.is_empty() || t.slug.as_str() > req.page_token.as_str())
                .collect();
            let page: Vec<Tenant> = rest.iter().take(size).map(|t| tenant_pb(t)).collect();
            let next_page_token = if rest.len() > size {
                page.last().map(|t| t.slug.clone()).unwrap_or_default()
            } else {
                String::new()
            };
            Ok(Response::new(ListTenantsResponse {
                tenants: page,
                next_page_token,
            }))
        })
        .await
    }

    async fn get_usage(&self, _request: Request<TenantRef>) -> Result<Response<Usage>, Status> {
        Err(Status::unimplemented(
            "the relay keeps its counters in memory and does not export them yet",
        ))
    }

    async fn get_figures(
        &self,
        _request: Request<GetFiguresRequest>,
    ) -> Result<Response<GetFiguresResponse>, Status> {
        Ok(Response::new(GetFiguresResponse { figures: figures() }))
    }
}

impl Admin {
    async fn set_suspended(
        &self,
        rpc: &'static str,
        req: TenantRef,
        suspend: bool,
    ) -> Result<Response<Tenant>, Status> {
        let slug_text = req.slug.clone();
        self.run(rpc, &slug_text, true, move |home| {
            let slug = parse_slug(&req.slug)?;
            let info = lib(home, tenants::set_suspended(home, slug.as_str(), suspend))?;
            Ok(Response::new(tenant_pb(&info)))
        })
        .await
    }
}
