use super::*;
use std::collections::HashMap;

mod address;
mod entity;
mod network;
mod security;
mod transaction;

fn roundtrip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let json = serde_json::to_string(value).expect("serialize");
    serde_json::from_str(&json).expect("deserialize")
}
