use axum::{
    extract::State,
    routing::post,
    Router,
    Json,
};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;

// --- NEW: Cryptography Imports ---
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

// 1. Define our Application State
// This struct holds our private signing key in memory so every request can use it.
// We wrap it in an `Arc` (Atomic Reference Counted) so it can be safely shared across Tokio's threads.
struct AppState {
    signing_key: SigningKey,
}

#[tokio::main]
async fn main() {
    // 2. Generate a secure, random Ed25519 Keypair when AEGIS boots up
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    println!("🔑 AEGIS Cryptographic Key Generated.");

    // Create our shared state
    let shared_state = Arc::new(AppState { signing_key });

    // 3. Define our router and pass the state to it
    let app = Router::new()
        .route("/mcp", post(intercept_mcp_request))
        .with_state(shared_state); // <-- Injecting the key into the router!

    // Bind and start the server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await.unwrap();
    println!("🛡️ AEGIS-MCP Proxy running on http://127.0.0.1:8080");

    axum::serve(listener, app).await.unwrap();
}

// 4. The Interceptor Function (Now with `State`)
async fn intercept_mcp_request(
    State(state): State<Arc<AppState>>, // <-- Extracting the key from Axum
    Json(payload): Json<Value>,
) -> Json<Value> {
    let start_time = Instant::now();
    println!("🚨 Intercepted MCP Payload: {:#?}", payload);

    // --- NEW: Cryptographic Signing Logic ---
    
    // Step A: Convert the JSON payload into a plain string so we can hash it
    let payload_string = serde_json::to_string(&payload).unwrap();
    
    // Step B: Create a SHA-256 Hash (Fingerprint) of the payload
    let mut hasher = Sha256::new();
    hasher.update(payload_string.as_bytes());
    let payload_hash = hasher.finalize();
    
    // Step C: Sign the hash using our Ed25519 Private Key
    let signature = state.signing_key.sign(&payload_hash);
    
    println!("🔐 SHA-256 Hash: {:x}", payload_hash);
    println!("✍️  Ed25519 Signature: {}", hex::encode(signature.to_bytes()));
    // ----------------------------------------

    // Forwarding Logic (Same as before)
    let client = reqwest::Client::new();
    let target_url = "https://httpbin.org/post";
    
    let response = client
        .post(target_url)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request")
        .json::<Value>()
        .await
        .expect("Failed to parse response");

    let duration = start_time.elapsed();
    println!("⏱️ Total Time (Including Crypto & Network): {:?}", duration);
    
    Json(response)
}