//! OpenAPI 3.1 description of the browser-safe API (issue #130).
//!
//! This document is the single source consumed by the checked-in TypeScript
//! client. It describes only the endpoints exposed on this boundary: there
//! are no signing, witness, DA or P2P operations.
use serde_json::{json, Value};

use crate::contract::API_VERSION;

/// Build the OpenAPI document. Kept as a function so tests can assert its
/// shape and the TS client generator can diff against it.
pub fn document() -> Value {
    let error_body = json!({
        "type": "object",
        "required": ["api_version", "request_id", "network", "read_height", "indexed_height", "error"],
        "properties": {
            "api_version": { "type": "integer", "const": API_VERSION },
            "request_id": { "type": "string" },
            "network": { "type": "string" },
            "read_height": { "type": "integer", "format": "uint64" },
            "indexed_height": { "type": "integer", "format": "uint64" },
            "error": {
                "type": "object",
                "required": ["code", "message"],
                "properties": {
                    "code": {
                        "type": "string",
                        "enum": [
                            "INVALID_REQUEST", "UNSUPPORTED_VERSION", "INVALID_TRANSACTION",
                            "DUPLICATE_REQUEST", "NOT_FOUND", "STALE_PROJECTION",
                            "NETWORK_MISMATCH", "UNAUTHORIZED", "INTERNAL"
                        ]
                    },
                    "message": { "type": "string" }
                }
            }
        }
    });
    let envelope = |data: Value| {
        json!({
            "allOf": [
                {
                    "type": "object",
                    "required": ["api_version", "request_id", "network", "read_height", "indexed_height", "data"],
                    "properties": {
                        "api_version": { "type": "integer", "const": API_VERSION },
                        "request_id": { "type": "string" },
                        "network": { "type": "string" },
                        "read_height": { "type": "integer", "format": "uint64" },
                        "indexed_height": { "type": "integer", "format": "uint64" },
                        "data": data
                    }
                }
            ]
        })
    };
    let page = json!({
        "type": "object",
        "required": ["kind", "items", "next_cursor", "stale"],
        "properties": {
            "kind": { "type": "string" },
            "items": { "type": "array", "items": { "type": "object" } },
            "next_cursor": { "type": ["string", "null"] },
            "stale": { "type": "boolean" }
        }
    });
    let receipt = json!({
        "type": "object",
        "required": ["tx_hash", "status", "height"],
        "properties": {
            "tx_hash": { "type": "string" },
            "status": { "type": "string" },
            "height": { "type": ["integer", "null"], "format": "uint64" }
        }
    });
    let chain = json!({
        "type": "object",
        "required": ["height", "state_root", "da_ref", "indexed_height", "lag", "stale"],
        "properties": {
            "height": { "type": "integer", "format": "uint64" },
            "state_root": { "type": "string" },
            "da_ref": { "type": ["string", "null"] },
            "indexed_height": { "type": "integer", "format": "uint64" },
            "lag": { "type": "integer", "format": "uint64" },
            "stale": { "type": "boolean" }
        }
    });
    let session = json!({
        "type": "object",
        "required": ["token", "api_version", "expires_in_secs"],
        "properties": {
            "token": { "type": "string" },
            "api_version": { "type": "integer" },
            "expires_in_secs": { "type": "integer", "format": "uint64" }
        }
    });
    let submit = json!({
        "type": "object",
        "required": ["version", "api_version", "tx_bytes"],
        "properties": {
            "version": { "type": "integer", "const": 1 },
            "api_version": { "type": "integer", "const": API_VERSION },
            "tx_bytes": {
                "type": "array",
                "items": { "type": "integer", "minimum": 0, "maximum": 255 },
                "description": "Canonical JSON bytes of an already-signed transaction. No key material is accepted."
            }
        }
    });

    let err_ref = json!({ "description": "Stable error envelope", "content": { "application/json": { "schema": error_body.clone() } } });
    let bearer = json!([{ "type": "http", "scheme": "bearer" }]);
    let req_id = json!({
        "name": "X-Request-Id", "in": "header", "required": false,
        "schema": { "type": "string", "maxLength": 128 },
        "description": "Idempotency key. Reuse with a different body returns DUPLICATE_REQUEST."
    });
    let page_params = json!([
        req_id.clone(),
        { "name": "cursor", "in": "query", "required": false, "schema": { "type": "string" } },
        { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer", "default": 50, "maximum": 100 } }
    ]);

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "WorkStream Browser API",
            "version": API_VERSION.to_string(),
            "description": "Versioned, browser-safe HTTPS facade. Clients keep signing keys locally and submit signed bytes. Read models are projections; the verifier journal remains the authority."
        },
        "servers": [{ "url": "https://localhost:{port}/", "description": "Local dev (operator-supplied certificate)" }],
        "paths": {
            "/v1/session": {
                "post": {
                    "summary": "Issue a short-lived session token",
                    "operationId": "issueSession",
                    "parameters": [req_id.clone()],
                    "responses": {
                        "200": { "description": "Session issued", "content": { "application/json": { "schema": envelope(session.clone()) } } },
                        "400": err_ref.clone()
                    }
                }
            },
            "/v1/submit": {
                "post": {
                    "summary": "Submit already-signed transaction bytes",
                    "operationId": "submitTransaction",
                    "security": bearer,
                    "parameters": [req_id.clone()],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": submit } } },
                    "responses": {
                        "200": { "description": "Accepted", "content": { "application/json": { "schema": envelope(json!({
                            "type": "object",
                            "required": ["tx_hash", "status", "height"],
                            "properties": {
                                "tx_hash": { "type": "string" },
                                "status": { "type": "string" },
                                "height": { "type": ["integer", "null"] }
                            }
                        })) } } },
                        "400": err_ref.clone(), "401": err_ref.clone(), "409": err_ref.clone(), "500": err_ref.clone()
                    }
                }
            },
            "/v1/receipt": {
                "get": {
                    "summary": "Look up a verified receipt by 0x-prefixed hash",
                    "operationId": "getReceipt",
                    "security": bearer,
                    "parameters": json!([req_id.clone(), { "name": "tx_hash", "in": "query", "required": true, "schema": { "type": "string" } }]),
                    "responses": {
                        "200": { "description": "Receipt", "content": { "application/json": { "schema": envelope(receipt.clone()) } } },
                        "401": err_ref.clone(), "404": err_ref.clone()
                    }
                }
            },
            "/v1/chain": {
                "get": {
                    "summary": "Verified tip and projection cursor",
                    "operationId": "getChain",
                    "security": bearer,
                    "parameters": [req_id.clone()],
                    "responses": {
                        "200": { "description": "Chain status", "content": { "application/json": { "schema": envelope(chain) } } },
                        "401": err_ref.clone(), "503": err_ref.clone()
                    }
                }
            },
            "/v1/tasks": {
                "get": {
                    "summary": "Page work items",
                    "operationId": "getTasks",
                    "security": bearer,
                    "parameters": page_params.clone(),
                    "responses": {
                        "200": { "description": "Work item page", "content": { "application/json": { "schema": envelope(page.clone()) } } },
                        "401": err_ref.clone(), "503": err_ref.clone()
                    }
                }
            },
            "/v1/reviews": {
                "get": {
                    "summary": "Page reviews / review queues",
                    "operationId": "getReviews",
                    "security": bearer,
                    "parameters": page_params.clone(),
                    "responses": {
                        "200": { "description": "Review page", "content": { "application/json": { "schema": envelope(page.clone()) } } },
                        "401": err_ref.clone(), "503": err_ref.clone()
                    }
                }
            },
            "/v1/receipts": {
                "get": {
                    "summary": "Page verified receipts",
                    "operationId": "getReceipts",
                    "security": bearer,
                    "parameters": page_params.clone(),
                    "responses": {
                        "200": { "description": "Receipt page", "content": { "application/json": { "schema": envelope(page.clone()) } } },
                        "401": err_ref.clone(), "503": err_ref.clone()
                    }
                }
            },
            "/v1/events": {
                "get": {
                    "summary": "Page projection events",
                    "operationId": "getEvents",
                    "security": bearer,
                    "parameters": page_params,
                    "responses": {
                        "200": { "description": "Event page", "content": { "application/json": { "schema": envelope(page) } } },
                        "401": err_ref.clone(), "503": err_ref.clone()
                    }
                }
            },
            "/v1/openapi.json": {
                "get": {
                    "summary": "This document",
                    "operationId": "getOpenApi",
                    "responses": { "200": { "description": "OpenAPI JSON" } }
                }
            }
        },
        "components": {
            "securitySchemes": { "bearerAuth": { "type": "http", "scheme": "bearer" } }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_describes_only_browser_safe_operations() {
        let doc = document();
        let paths = doc["paths"].as_object().unwrap();
        for forbidden in ["sign", "prove", "witness", "da/post", "p2p"] {
            assert!(
                !paths.keys().any(|p| p.contains(forbidden)),
                "path must not expose {forbidden}"
            );
        }
        assert!(paths.contains_key("/v1/submit"));
        assert!(paths.contains_key("/v1/chain"));
        assert_eq!(doc["info"]["version"], API_VERSION.to_string());
    }

    #[test]
    fn document_matches_checked_in_schema() {
        let checked_in: Value =
            serde_json::from_str(include_str!("../client/openapi.json")).unwrap();
        assert_eq!(document(), checked_in, "client schema must be regenerated");
    }
}
