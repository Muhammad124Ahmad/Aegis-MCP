use axum::{
    extract::State,
    routing::{get, post}, // <-- UPDATE: Added `get` to our imports
    Router,
    Json,
};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

// 1. Update Application State to include our embedded database
struct AppState {
    signing_key: SigningKey,
    db: sled::Db, // <-- NEW: Adding the Sled database to our state
}

#[tokio::main]
async fn main() {
    // Generate Cryptographic Key
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    println!("🔑 AEGIS Cryptographic Key Generated.");

    // --- NEW: Initialize the Sled Database ---
    // This will automatically create a folder named "aegis_ledger_db" in your project directory
    let db = sled::open("aegis_ledger_db").expect("Failed to open Sled database");
    println!("💾 AEGIS Immutable Ledger Database Online.");
    // -----------------------------------------

    // Create our shared state
    let shared_state = Arc::new(AppState { signing_key, db });

    // Define our router
    let app = Router::new()
        .route("/mcp", post(intercept_mcp_request))
        .route("/logs", get(view_logs)) // <-- NEW: Route to view our ledger
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8888").await.unwrap();
    println!("🛡️ AEGIS-MCP Proxy running on http://127.0.0.1:8888");

    axum::serve(listener, app).await.unwrap();
}

// 4. The Interceptor Function
async fn intercept_mcp_request(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let start_time = Instant::now();
    println!("🚨 Intercepted MCP Payload: {:#?}", payload);

    // Step A: Convert to string for hashing
    let payload_string = serde_json::to_string(&payload).unwrap();
    
    // Step B: Create a SHA-256 Hash
    let mut hasher = Sha256::new();
    hasher.update(payload_string.as_bytes());
    let payload_hash = hasher.finalize();
    let hash_hex = hex::encode(payload_hash); // Convert hash to readable text
    
    // Step C: Sign the hash
    let signature = state.signing_key.sign(&payload_hash);
    let signature_hex = hex::encode(signature.to_bytes()); // Convert signature to readable text
    
    println!("🔐 SHA-256 Hash: {}", hash_hex);
    println!("✍️  Ed25519 Signature: {}", signature_hex);

    // --- NEW: Step D: Save to the Immutable Ledger ---
    // We create a JSON object containing both the payload and its cryptographic signature
    let log_entry = serde_json::json!({
        "payload": payload,
        "signature": signature_hex
    });

    // We save it to the database! 
    // The "Key" is the Hash, and the "Value" is our log entry.
    state.db.insert(
        hash_hex.as_bytes(), 
        log_entry.to_string().as_bytes()
    ).expect("Failed to write to ledger");
    
    // Force the database to flush to disk immediately for maximum safety
    state.db.flush().unwrap();
    println!("💽 Cryptographic log safely written to disk!");
    // -------------------------------------------------

    // Forwarding Logic
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
    println!("⏱️ Total Time (Including Crypto, DB Write & Network): {:?}", duration);
    
    Json(response)
}

async fn view_logs(State(state): State<Arc<AppState>>) -> Json<Value> {
    let mut logs = Vec::new();

    // Loop through every entry in the embedded database
    for result in state.db.iter() {
        if let Ok((_key, value)) = result {
            // Convert the raw database bytes back into a readable string
            if let Ok(log_string) = String::from_utf8(value.to_vec()) {
                // Parse the string back into a JSON object
                if let Ok(json_log) = serde_json::from_str::<Value>(&log_string) {
                    logs.push(json_log);
                }
            }
        }
    }

    // Return the array of logs to the user
    Json(serde_json::json!(logs))
}