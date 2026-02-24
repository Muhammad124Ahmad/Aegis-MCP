use axum::{
    routing::post,
    Router,
    Json,
};
use serde_json::Value;
use std::time::Instant;

#[tokio::main]
async fn main() {
    // Define our router
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
    
    // --- NEW: Forwarding Logic ---
    // 2. Create our HTTP client
    let client = reqwest::Client::new();
    
    // 3. Define our target (Our "Fake" MCP Server for testing)
    let target_url = "https://httpbin.org/post";
    println!("➡️ Forwarding request to: {}", target_url);
    
    // 4. Send the payload and await the response
    let response = client
        .post(target_url)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send request to target server") // Basic error handling
        .json::<Value>() // Parse the response back into JSON
        .await
        .expect("Failed to parse response JSON");
    // ------------------------------

    // 5. Stop the stopwatch
    let duration = start_time.elapsed();
    
    // Note: Because we are making a real network call to the internet (httpbin), 
    // this time will be much higher (e.g., 200ms+). This is normal network lag, 
    // NOT AEGIS processing overhead! When we run things locally, it drops back down.
    println!("⏱️ AEGIS Total Round-Trip Time: {:?}", duration);
    
    // 6. Return the response from the destination server back to the user
    Json(response)
}