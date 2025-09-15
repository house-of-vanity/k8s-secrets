use anyhow::Result;
use askama::Template;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use clap::Parser;
use k8s_openapi::api::core::v1::Secret;
use kube::{Api, Client};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{totp, Sha1};
use tracing::{error, info};
use tracing_subscriber;
use url::Url;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "3000")]
    port: u16,

    #[arg(short, long, value_delimiter = ',', help = "Secret names to display (comma-separated)")]
    secrets: Vec<String>,

    #[arg(short, long, default_value = "default")]
    namespace: String,
}

#[derive(Clone)]
struct AppState {
    client: Client,
    secret_names: Vec<String>,
    namespace: String,
}

#[derive(Serialize)]
struct SecretData {
    name: String,
    data: Vec<(String, String)>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    secrets: Vec<SecretData>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SecretQuery {
    name: String,
    field: String,
}

async fn read_secrets(state: &AppState) -> Result<Vec<SecretData>> {
    let secrets_api: Api<Secret> = Api::namespaced(state.client.clone(), &state.namespace);
    let mut result = Vec::new();

    for secret_name in &state.secret_names {
        match secrets_api.get(secret_name).await {
            Ok(secret) => {
                let mut data_pairs = Vec::new();
                
                if let Some(data) = secret.data {
                    for (key, value) in data {
                        let decoded = String::from_utf8_lossy(&value.0).to_string();
                        data_pairs.push((key, decoded));
                    }
                } else if let Some(string_data) = secret.string_data {
                    for (key, value) in string_data {
                        data_pairs.push((key, value));
                    }
                }
                
                data_pairs.sort_by(|a, b| a.0.cmp(&b.0));
                
                result.push(SecretData {
                    name: secret_name.clone(),
                    data: data_pairs,
                });
            }
            Err(e) => {
                error!("Failed to read secret {}: {}", secret_name, e);
                result.push(SecretData {
                    name: secret_name.clone(),
                    data: vec![("error".to_string(), format!("Failed to read: {}", e))],
                });
            }
        }
    }
    
    Ok(result)
}

async fn index_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    info!("Handling request, fetching secrets: {:?}", state.secret_names);
    
    match read_secrets(&state).await {
        Ok(secrets) => {
            let template = IndexTemplate {
                secrets,
                error: None,
            };
            
            match template.render() {
                Ok(html) => Html(html).into_response(),
                Err(e) => {
                    error!("Template render error: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Template render error").into_response()
                }
            }
        }
        Err(e) => {
            error!("Failed to read secrets: {}", e);
            let template = IndexTemplate {
                secrets: vec![],
                error: Some(format!("Failed to read secrets: {}", e)),
            };
            
            match template.render() {
                Ok(html) => Html(html).into_response(),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to read secrets").into_response(),
            }
        }
    }
}

async fn health_handler() -> impl IntoResponse {
    "OK"
}

fn generate_totp_code(otpauth_url: &str) -> Option<String> {
    let url = Url::parse(otpauth_url).ok()?;
    
    if url.scheme() != "otpauth" || url.host_str() != Some("totp") {
        return None;
    }
    
    let mut secret = None;
    let mut period = 30u64;
    
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "secret" => secret = Some(value.to_string()),
            "period" => period = value.parse().unwrap_or(30),
            _ => {}
        }
    }
    
    let secret = secret?;
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret)?;
    
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs() / period;
    
    let code = totp::<Sha1>(&decoded, time);
    Some(code)
}

async fn secret_handler(
    Query(params): Query<SecretQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    info!("Fetching secret: {} field: {}", params.name, params.field);
    
    let secrets_api: Api<Secret> = Api::namespaced(state.client.clone(), &state.namespace);
    
    match secrets_api.get(&params.name).await {
        Ok(secret) => {
            if let Some(data) = secret.data {
                if let Some(value) = data.get(&params.field) {
                    let decoded = String::from_utf8_lossy(&value.0).to_string();
                    
                    // Check if it's a TOTP URL and generate code
                    if decoded.starts_with("otpauth://totp/") {
                        if let Some(code) = generate_totp_code(&decoded) {
                            return code.into_response();
                        }
                    }
                    
                    return decoded.into_response();
                }
            }
            
            if let Some(string_data) = secret.string_data {
                if let Some(value) = string_data.get(&params.field) {
                    // Check if it's a TOTP URL and generate code
                    if value.starts_with("otpauth://totp/") {
                        if let Some(code) = generate_totp_code(value) {
                            return code.into_response();
                        }
                    }
                    
                    return value.clone().into_response();
                }
            }
            
            (StatusCode::NOT_FOUND, format!("Field '{}' not found in secret '{}'", params.field, params.name)).into_response()
        }
        Err(e) => {
            error!("Failed to read secret {}: {}", params.name, e);
            (StatusCode::NOT_FOUND, format!("Secret '{}' not found: {}", params.name, e)).into_response()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    if args.secrets.is_empty() {
        error!("No secret names provided. Use --secrets flag with comma-separated secret names");
        std::process::exit(1);
    }
    
    info!("Starting secret-reader service");
    info!("Configured to read secrets: {:?}", args.secrets);
    info!("Namespace: {}", args.namespace);
    
    let client = Client::try_default().await?;
    
    let state = Arc::new(AppState {
        client,
        secret_names: args.secrets,
        namespace: args.namespace,
    });
    
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/health", get(health_handler))
        .route("/secret", get(secret_handler))
        .with_state(state);
    
    let addr = format!("0.0.0.0:{}", args.port);
    info!("Server listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}
