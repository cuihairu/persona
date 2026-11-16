use super::*;

use serde_json::json;
use std::io::{Cursor, Write};

mod container;
mod fields;
mod mapping;

fn make_1pux(attributes: &str, data: &str) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    writer.start_file("export.attributes", options).unwrap();
    writer.write_all(attributes.as_bytes()).unwrap();
    writer.start_file("export.data", options).unwrap();
    writer.write_all(data.as_bytes()).unwrap();
    writer.finish().unwrap().into_inner()
}

fn attributes_json(version: u64) -> String {
    json!({ "version": version, "description": "test export", "createdAt": 0 }).to_string()
}

fn export_data(items: serde_json::Value) -> String {
    json!({
        "accounts": [{
            "attrs": { "uuid": "acc-1", "name": "Account" },
            "vaults": [{
                "attrs": { "uuid": "vault-1", "name": "Personal" },
                "items": items
            }]
        }]
    })
    .to_string()
}

fn plan_from_items(items: serde_json::Value) -> ImportPlan {
    let bytes = make_1pux(&attributes_json(3), &export_data(items));
    let export = parse_1pux(&bytes).unwrap();
    plan_import(&export)
}

fn login_item() -> serde_json::Value {
    json!({
        "uuid": "item-1",
        "categoryUuid": "001",
        "state": "ACTIVE",
        "favIndex": 2,
        "createdAt": 1600000000,
        "updatedAt": 1600000100,
        "overview": {
            "title": "Example",
            "url": "https://example.com",
            "urls": [
                { "label": "website", "href": "https://example.com" },
                { "label": "login", "href": "https://example.com/login" }
            ],
            "tags": ["web", " work "]
        },
        "details": {
            "loginFields": [
                { "id": "username", "type": "T", "designation": "username", "value": "alice@example.com" },
                { "id": "password", "type": "P", "designation": "password", "value": "hunter2" }
            ],
            "notesPlain": "note text",
            "sections": []
        }
    })
}
