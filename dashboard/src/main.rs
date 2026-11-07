use std::env;
use std::fs;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

const DASHBOARD_HTML: &str = r#"<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
  <title>NoLog Dashboard</title>
  <style>
    :root { color-scheme: dark; font-family: system-ui, sans-serif; }
    body { background:#111827; color:#e5e7eb; margin:0; padding:2rem; }
    main { max-width:1100px; margin:auto; }
    input,button { border:1px solid #374151; border-radius:.5rem; padding:.65rem; background:#1f2937; color:#e5e7eb; }
    button { cursor:pointer; background:#2563eb; border-color:#2563eb; }
    .toolbar { display:flex; gap:.6rem; margin:1rem 0 2rem; }
    .toolbar input { flex:1; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:1rem; }
    .card { background:#1f2937; border-radius:.8rem; padding:1rem; }
    .value { display:block; font-size:2rem; margin-top:.35rem; color:#93c5fd; }
    #status { color:#9ca3af; }
  </style>
</head>
<body>
<main>
  <h1>NoLog Dashboard</h1>
  <p id="status">Les statistiques sont agrégées et ne contiennent pas d’identifiants ni de destinations.</p>
  <div class="toolbar">
    <input id="token" type="password" placeholder="Token du dashboard" autocomplete="off">
    <button id="refresh">Actualiser</button>
  </div>
  <section class="grid" id="cards"></section>
</main>
<script>
const fields = [
  ["active_sessions", "Sessions actives"],
  ["users_total", "Événements utilisateurs"],
  ["requests_total", "Requêtes"],
  ["bytes_in", "Octets entrants"],
  ["bytes_out", "Octets sortants"],
  ["errors_total", "Erreurs"],
  ["tor_slow_connections", "Connexions Tor lentes"],
  ["tor_newnym_total", "Rotations Tor"],
];
async function refresh() {
  const token = document.getElementById("token").value;
  const status = document.getElementById("status");
  try {
    const response = await fetch("/api/stats", { headers: { "Authorization": "Bearer " + token }, cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    document.getElementById("cards").innerHTML = fields.map(([key,label]) =>
      `<article class="card"><span>${label}</span><strong class="value">${Number(data[key] || 0).toLocaleString("fr-FR")}</strong></article>`
    ).join("");
    status.textContent = "Dernière mise à jour : " + new Date().toLocaleTimeString();
  } catch (error) {
    status.textContent = "Statistiques indisponibles : " + error.message;
  }
}
document.getElementById("refresh").addEventListener("click", refresh);
setInterval(refresh, 5000);
</script>
</body>
</html>"#;

#[derive(Debug, Default, Serialize, Clone)]
struct Stats {
    active_sessions: u64,
    users_total: u64,
    requests_total: u64,
    bytes_in: u64,
    bytes_out: u64,
    errors_total: u64,
    tor_slow_connections: u64,
    tor_newnym_total: u64,
}

#[derive(Debug, Deserialize)]
struct MetricsEvent {
    #[serde(default)]
    active_sessions_delta: i64,
    #[serde(default)]
    users: u64,
    #[serde(default)]
    requests: u64,
    #[serde(default)]
    bytes_in: u64,
    #[serde(default)]
    bytes_out: u64,
    #[serde(default)]
    errors: u64,
    #[serde(default)]
    tor_slow_connections: u64,
    #[serde(default)]
    tor_newnym: u64,
}

struct AppState {
    stats: Mutex<Stats>,
    dashboard_token: String,
    ingest_token: String,
}

impl AppState {
    fn update(&self, event: MetricsEvent) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.active_sessions = if event.active_sessions_delta.is_negative() {
                stats
                    .active_sessions
                    .saturating_sub(event.active_sessions_delta.unsigned_abs())
            } else {
                stats
                    .active_sessions
                    .saturating_add(event.active_sessions_delta as u64)
            };
            stats.users_total = stats.users_total.saturating_add(event.users);
            stats.requests_total = stats.requests_total.saturating_add(event.requests);
            stats.bytes_in = stats.bytes_in.saturating_add(event.bytes_in);
            stats.bytes_out = stats.bytes_out.saturating_add(event.bytes_out);
            stats.errors_total = stats.errors_total.saturating_add(event.errors);
            stats.tor_slow_connections = stats
                .tor_slow_connections
                .saturating_add(event.tor_slow_connections);
            stats.tor_newnym_total = stats.tor_newnym_total.saturating_add(event.tor_newnym);
        }
    }

    fn snapshot(&self) -> Stats {
        self.stats
            .lock()
            .map(|stats| stats.clone())
            .unwrap_or_default()
    }
}

fn bearer_matches(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| !expected.is_empty() && value.as_bytes() == expected.as_bytes())
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
}

async fn dashboard() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (headers, Html(DASHBOARD_HTML))
}

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn stats(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !bearer_matches(&headers, &state.dashboard_token) {
        return unauthorized();
    }
    let mut response = Json(state.snapshot()).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn ingest(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(event): Json<MetricsEvent>,
) -> Response {
    if !bearer_matches(&headers, &state.ingest_token) {
        return unauthorized();
    }
    state.update(event);
    StatusCode::NO_CONTENT.into_response()
}

async fn prometheus(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !bearer_matches(&headers, &state.dashboard_token) {
        return unauthorized();
    }
    let stats = state.snapshot();
    let body = format!(
        "# TYPE nolog_active_sessions gauge\nnolog_active_sessions {}\n# TYPE nolog_users_total counter\nnolog_users_total {}\n# TYPE nolog_requests_total counter\nnolog_requests_total {}\n# TYPE nolog_bytes_in_total counter\nnolog_bytes_in_total {}\n# TYPE nolog_bytes_out_total counter\nnolog_bytes_out_total {}\n# TYPE nolog_errors_total counter\nnolog_errors_total {}\n# TYPE nolog_tor_slow_connections_total counter\nnolog_tor_slow_connections_total {}\n# TYPE nolog_tor_newnym_total counter\nnolog_tor_newnym_total {}\n",
        stats.active_sessions,
        stats.users_total,
        stats.requests_total,
        stats.bytes_in,
        stats.bytes_out,
        stats.errors_total,
        stats.tor_slow_connections,
        stats.tor_newnym_total,
    );
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = env::var("NOLOG_DASHBOARD_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let dashboard_token = load_secret("NOLOG_DASHBOARD_TOKEN", "NOLOG_DASHBOARD_TOKEN_FILE")?;
    let ingest_token = load_secret("NOLOG_INGEST_TOKEN", "NOLOG_INGEST_TOKEN_FILE")?;
    if dashboard_token.len() < 32 || ingest_token.len() < 32 {
        return Err("dashboard and ingest tokens must contain at least 32 characters".into());
    }

    let address: SocketAddr = bind.parse()?;
    let state = Arc::new(AppState {
        stats: Mutex::new(Stats::default()),
        dashboard_token,
        ingest_token,
    });
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/healthz", get(healthz))
        .route("/api/stats", get(stats))
        .route("/internal/events", post(ingest))
        .route("/metrics", get(prometheus))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn load_secret(env_name: &str, file_env_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = if let Ok(path) = env::var(file_env_name) {
        fs::read_to_string(path)?
    } else {
        env::var(env_name)?
    };
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(format!("{env_name} must not be empty").into());
    }
    Ok(value)
}
