use axum::{
    routing::post,
    Router,
    Json,
};
use serde_json::Value;
use std::time::Instant; // <-- NEW: Import Rust's high-precision timer

#[tokio::main]
async fn main() {
    // Define our router (The "Ingress" layer)
    let app = Router::new()
        .route("/mcp", post(intercept_mcp_request));

    // Bind the TCP listener
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await.unwrap();
    println!("🛡️ AEGIS-MCP Proxy running on http://127.0.0.1:8080");

    // Start the server
    axum::serve(listener, app).await.unwrap();
}

// The Interceptor Function
async fn intercept_mcp_request(Json(payload): Json<Value>) -> Json<Value> {
    // 1. Start the stopwatch
    let start_time = Instant::now();

    println!("🚨 Intercepted MCP Payload: {:#?}", payload);
    
    // 2. Stop the stopwatch and calculate duration
    let duration = start_time.elapsed();
    
    // 3. Print the performance metric
    // Using {:?} will automatically format it in milliseconds (ms) or microseconds (µs)
    println!("⏱️ AEGIS Processing Overhead: {:?}", duration);
    
    // Pass it back
    Json(payload)
}