use axum::{
    extract::State,
    routing::{get, post},
    Router,
    Json,
};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

// Cryptography Imports
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

// AI Engine Imports
use ort::session::Session;
use tokenizers::Tokenizer;
use ndarray::Array2;

struct AppState {
    signing_key: SigningKey,
    db: sled::Db,
    tokenizer: Tokenizer,
    ai_model: Mutex<Session>, 
}

#[tokio::main]
async fn main() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    println!("🔑 AEGIS Cryptographic Key Generated.");

    let db = sled::open("aegis_ledger_db").expect("Failed to open Sled database");
    println!("💾 AEGIS Immutable Ledger Database Online.");

    println!("🧠 Loading AI Tokenizer...");
    let tokenizer = Tokenizer::from_file("models/tokenizer.json")
        .expect("Failed to load tokenizer.json");

    println!("🧠 Loading ONNX Neural Network...");
    let ai_model = Session::builder()
        .expect("Failed to create ONNX session builder")
        .commit_from_file("models/model.onnx")
        .expect("Failed to load model.onnx into memory!");
    println!("⚡ AI Brain Successfully Loaded into CPU Cache!");

    let shared_state = Arc::new(AppState { 
        signing_key, 
        db, 
        tokenizer, 
        ai_model: Mutex::new(ai_model), 
    });

    let app = Router::new()
        .route("/mcp", post(intercept_mcp_request))
        .route("/logs", get(view_logs))
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
    println!("🚨 Original MCP Payload: {:#?}", payload);

    let text_to_analyze = payload["params"]["name"].as_str().unwrap_or("Unknown");
    let encoding = state.tokenizer.encode(text_to_analyze, true).unwrap();
    
    let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&x| x as i64).collect();
    let attention_mask: Vec<i64> = encoding.get_attention_mask().iter().map(|&x| x as i64).collect();
    let token_type_ids: Vec<i64> = encoding.get_type_ids().iter().map(|&x| x as i64).collect();

    let sequence_length = input_ids.len();
    let input_ids_array = Array2::from_shape_vec((1, sequence_length), input_ids.clone()).unwrap();
    let attention_mask_array = Array2::from_shape_vec((1, sequence_length), attention_mask).unwrap();
    let token_type_ids_array = Array2::from_shape_vec((1, sequence_length), token_type_ids).unwrap();

    let input_ids_tensor = ort::value::Tensor::from_array(input_ids_array).unwrap();
    let attention_mask_tensor = ort::value::Tensor::from_array(attention_mask_array).unwrap();
    let token_type_ids_tensor = ort::value::Tensor::from_array(token_type_ids_array).unwrap();

    let ai_inputs = ort::inputs![
        "input_ids" => input_ids_tensor,
        "attention_mask" => attention_mask_tensor,
        "token_type_ids" => token_type_ids_tensor,
    ]; 

    // --- Thread-Safe AI Execution & Redaction ---
    let ai_start = Instant::now();
    let mut entity_spans = Vec::new();
    
    { // Create a strict scope for the Mutex lock
        let mut locked_model = state.ai_model.lock().await; 
        let ai_outputs = locked_model.run(ai_inputs).expect("AI Inference Failed!"); 
        
        // NEW: ort v2 returns a tuple (Shape, Flattened Data Slice)
        let (shape, logits_data) = ai_outputs["logits"].try_extract_tensor::<f32>().unwrap();
        
        let num_labels = shape[2] as usize;
        let offsets = encoding.get_offsets();

        // Loop through every single word/token
        for i in 0..sequence_length {
            let mut max_val = f32::MIN;
            let mut max_idx = 0;
            
            // Find the category with the highest probability
            for j in 0..num_labels {
                // NEW: Convert 3D matrix coordinates into a 1D flat array index
                let flat_index = (i * num_labels) + j;
                let val = logits_data[flat_index];
                
                if val > max_val {
                    max_val = val;
                    max_idx = j;
                }
            }
            
            // If the AI says it is an Entity (> 0), record the byte offsets!
            if max_idx > 0 {
                let (start, end) = offsets[i];
                if start != end {
                    entity_spans.push((start, end));
                }
            }
        }
    } // The Mutex lock is instantly dropped here!
    
    let ai_duration = ai_start.elapsed();
    println!("🎯 AI Inference & Math Parsing Complete! Took: {:?}", ai_duration);

    // --- Apply the Redaction Mask ---
    // We convert the string to raw bytes, mask the PII with '*', and convert it back
    let mut redacted_bytes = text_to_analyze.as_bytes().to_vec();
    for (start, end) in entity_spans {
        for b in start..end {
            redacted_bytes[b] = b'*';
        }
    }
    let redacted_text = String::from_utf8(redacted_bytes).unwrap();
    println!("🛡️ AI Redacted Text: '{}'", redacted_text);

    // --- Create the SAFE Payload ---
    let mut safe_payload = payload.clone();
    safe_payload["params"]["name"] = serde_json::Value::String(redacted_text);

    // ==========================================
    // SECURE FORWARDING & LOGGING (Using the SAFE Payload)
    // ==========================================
    
    let payload_string = serde_json::to_string(&safe_payload).unwrap();
    
    let mut hasher = Sha256::new();
    hasher.update(payload_string.as_bytes());
    let payload_hash = hasher.finalize();
    let hash_hex = hex::encode(payload_hash);
    
    let signature = state.signing_key.sign(&payload_hash);
    let signature_hex = hex::encode(signature.to_bytes());
    
    let log_entry = serde_json::json!({
        "payload": safe_payload,
        "signature": signature_hex
    });

    state.db.insert(
        hash_hex.as_bytes(), 
        log_entry.to_string().as_bytes()
    ).expect("Failed to write to ledger");
    state.db.flush().unwrap();
    
    let aegis_overhead = start_time.elapsed();
    println!("⏱️ Total AEGIS Interception Overhead: {:?}", aegis_overhead);

    // Forward the SECURE payload to the destination
    let client = reqwest::Client::new();
    let target_url = "https://httpbin.org/post";
    
    let response = client
        .post(target_url)
        .json(&safe_payload) // <-- Sending the masked JSON!
        .send()
        .await
        .expect("Failed to send request")
        .json::<Value>()
        .await
        .expect("Failed to parse response");
    
    Json(response)
}

// 5. The Ledger Viewer Function
async fn view_logs(State(state): State<Arc<AppState>>) -> Json<Value> {
    let mut logs = Vec::new();
    for result in state.db.iter() {
        if let Ok((_key, value)) = result {
            if let Ok(log_string) = String::from_utf8(value.to_vec()) {
                if let Ok(json_log) = serde_json::from_str::<Value>(&log_string) {
                    logs.push(json_log);
                }
            }
        }
    }
    Json(serde_json::json!(logs))
}