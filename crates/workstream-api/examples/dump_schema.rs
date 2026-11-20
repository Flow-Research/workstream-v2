//! Emit the OpenAPI document consumed by the generated TypeScript client.
//! Run with `cargo run -p workstream-api --example dump_schema > client/openapi.json`.
fn main() {
    print!(
        "{}",
        serde_json::to_string_pretty(&workstream_api::openapi::document()).unwrap()
    );
}
