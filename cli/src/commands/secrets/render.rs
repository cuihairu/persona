use anyhow::{bail, Context, Result};
use persona_core::PersonaService;
use serde::Serialize;
use std::collections::BTreeMap;

use crate::config::CliConfig;
use crate::utils::prompt::PromptUi;

use super::open_unlocked;
use super::refs::{parse_kv_pairs, resolve_ref, valid_key, SecretRef};

// -----------------------------------------------------------------------
// k8s（Secret 清单渲染；JSON 落 base64，kubectl 侧按需 apply）
// -----------------------------------------------------------------------

#[derive(Serialize)]
#[allow(non_snake_case)] // field names double as the serialized YAML keys
pub(super) struct K8sSecretManifest {
    pub(super) apiVersion: &'static str,
    pub(super) kind: &'static str,
    #[serde(rename = "type")]
    pub(super) secret_type: &'static str,
    pub(super) metadata: K8sObjectMeta,
    pub(super) data: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub(super) struct K8sObjectMeta {
    pub(super) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) labels: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) annotations: Option<BTreeMap<String, String>>,
}

pub(super) async fn render_k8s(
    config: &CliConfig,
    ui: &dyn PromptUi,
    name: &str,
    namespace: Option<&str>,
    key_specs: &[String],
    label_specs: &[String],
    annotation_specs: &[String],
) -> Result<()> {
    if !valid_key(name, false) {
        bail!("--name {name:?} is not a valid Kubernetes object name");
    }
    if let Some(ns) = namespace {
        if !valid_key(ns, false) {
            bail!("--namespace {ns:?} is not a valid namespace name");
        }
    }
    if key_specs.is_empty() {
        bail!("at least one --key KEY=REF is required");
    }

    let mut key_refs = Vec::with_capacity(key_specs.len());
    for spec in key_specs {
        let (key, raw) = spec
            .split_once('=')
            .with_context(|| format!("--key {spec:?} must be KEY=REF"))?;
        if !valid_key(key, false) {
            bail!("--key {spec:?} has an invalid key (use [A-Za-z0-9._-])");
        }
        key_refs.push((key.to_string(), SecretRef::parse(raw)?));
    }
    let labels = parse_kv_pairs(label_specs, "labels")?;
    let annotations = parse_kv_pairs(annotation_specs, "annotation")?;

    let service = open_unlocked(config, ui).await?;
    use base64::Engine;
    let mut data = BTreeMap::new();
    for (key, secret_ref) in &key_refs {
        let value = resolve_ref(&service, secret_ref)
            .await
            .with_context(|| format!("failed to resolve {secret_ref}"))?;
        data.insert(
            key.clone(),
            base64::engine::general_purpose::STANDARD.encode(value.as_bytes()),
        );
    }

    let manifest = K8sSecretManifest {
        apiVersion: "v1",
        kind: "Secret",
        secret_type: "Opaque",
        metadata: K8sObjectMeta {
            name: name.to_string(),
            namespace: namespace.map(str::to_string),
            labels: (!labels.is_empty()).then_some(labels),
            annotations: (!annotations.is_empty()).then_some(annotations),
        },
        data,
    };
    let yaml = serde_yaml::to_string(&manifest).context("failed to serialize manifest")?;
    print!("{yaml}");
    Ok(())
}

// -----------------------------------------------------------------------
// external（Terraform external provider 协议助手）
// -----------------------------------------------------------------------

/// external 协议核心（纯函数）：stdin JSON 对象 `{"NAME":"REF"}` →
/// stdout JSON 对象 `{"NAME":"明文"}`。保持插入顺序（serde_json 默认
/// BTreeMap 有序即可——Terraform 只按 key 取值，顺序无语义）。
pub(crate) async fn resolve_external_map(
    service: &PersonaService,
    input: &str,
) -> Result<serde_json::Value> {
    let query: serde_json::Value =
        serde_json::from_str(input).context("stdin is not valid JSON")?;
    let obj = query
        .as_object()
        .with_context(|| "external query must be a JSON object of NAME=REF")?;
    let mut out = serde_json::Map::with_capacity(obj.len());
    for (name, raw) in obj {
        let raw = raw
            .as_str()
            .with_context(|| format!("query value for {name:?} must be a string REF"))?;
        let secret_ref = SecretRef::parse(raw)?;
        let value = resolve_ref(service, &secret_ref)
            .await
            .with_context(|| format!("failed to resolve {secret_ref}"))?;
        out.insert(name.clone(), serde_json::Value::String(value));
    }
    Ok(serde_json::Value::Object(out))
}

pub(super) async fn render_external(config: &CliConfig, ui: &dyn PromptUi) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let mut input = String::new();
    tokio::io::stdin()
        .read_to_string(&mut input)
        .await
        .context("failed to read stdin")?;
    let service = open_unlocked(config, ui).await?;
    let out = resolve_external_map(&service, &input).await.map_err(|e| {
        eprintln!("{e:#}");
        e
    })?;
    println!("{out}");
    Ok(())
}
