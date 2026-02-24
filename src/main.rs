use axum::{
    routing::post,
    Router,
    Json,
};
use serde_json::Value;

#[tokio::main]
async fn main() {
    // 1. Define our router (The "Ingress" layer)
    let app = Router::new()
        .route("/mcp", post(intercept_mcp_request));

    // 2. Bind the TCP listener using Tokio (The modern Axum 0.7+ way)
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await.unwrap();
    println!("🛡️ AEGIS-MCP Proxy running on http://127.0.0.1:8080");

    // 3. Start the server
    axum::serve(listener, app).await.unwrap();
}

// 4. The Interceptor Function
async fn intercept_mcp_request(Json(payload): Json<Value>) -> Json<Value> {
    println!("🚨 Intercepted MCP Payload: {:#?}", payload);
    
    // Pass it back to prove the connection works
    Json(payload)
}