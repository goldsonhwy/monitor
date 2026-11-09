//! Fetch and cache hardware benchmark reports from NodeQuality.

use std::collections::HashMap;
use std::io::Read;
use std::str;
use std::time::Duration;

use anyhow::{anyhow, Result};
use base64::Engine;
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use tracing::{info, warn};

use crate::{db::Node, App, Shared};

const API: &str = "https://api.nodequality.com";
const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36";
const TTL: i64 = 7 * 24 * 60 * 60;
const MAX_ZIP: usize = 12 << 20;
const MAX_JSON: usize = 24 << 20;

pub async fn watch(app: Shared) {
    loop {
        if let Err(error) = refresh_one(&app).await {
            warn!("refreshing NodeQuality benchmark cache failed: {error:#}");
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

pub async fn refresh_now(app: &Shared) -> Result<()> {
    refresh_one(app).await
}

async fn refresh_one(app: &Shared) -> Result<()> {
    let mut total_refreshed = 0;
    loop {
        match refresh_batch(app).await? {
            0 => break,
            count => total_refreshed += count,
        }
    }
    if total_refreshed > 0 {
        info!(refreshed = total_refreshed, "NodeQuality hardware benchmark refresh completed");
    }
    Ok(())
}

async fn refresh_batch(app: &Shared) -> Result<usize> {
    let _guard = app.nq_refresh.lock().await;
    let now = chrono::Utc::now().timestamp();
    let nodes = app.db.nodes_needing_nq(now, TTL, 1)?;
    let mut processed = 0;
    for (id, url) in nodes {
        match fetch_benchmark(app, &url).await {
            Ok(data) => {
                let encoded = data.to_string();
                app.db.save_nq_benchmark_cache(id, &url, now, &encoded)?;
                app.nq_benchmarks.write().unwrap_or_else(|e| e.into_inner()).insert(id, (url.clone(), data));
                processed += 1;
            }
            Err(error) => {
                warn!(node_id = id, source = %url, "fetching NodeQuality hardware report failed: {error:#}");
                app.db.save_nq_benchmark_cache(id, &url, now, "null")?;
                processed += 1;
            }
        }
    }
    Ok(processed)
}

pub fn cached(app: &App, node: &Node) -> Option<Value> {
    if node.nq_link_url.is_empty() {
        return None;
    }
    if let Some((source, data)) = app.nq_benchmarks.read().unwrap_or_else(|e| e.into_inner()).get(&node.id) {
        if source == &node.nq_link_url {
            return Some(data.clone());
        }
    }
    if let Ok(Some((source, cached_at, encoded))) = app.db.get_nq_benchmark_cache(node.id) {
        if source == node.nq_link_url
            && encoded != "null"
            && chrono::Utc::now().timestamp().saturating_sub(cached_at) < TTL
        {
            if let Ok(data) = serde_json::from_str::<Value>(&encoded) {
                app.nq_benchmarks
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(node.id, (source, data.clone()));
                return Some(data);
            }
        }
    }
    None
}

async fn fetch_benchmark(app: &App, page_url: &str) -> Result<Value> {
    let token = page_url
        .strip_prefix("https://nodequality.com/r/")
        .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_alphanumeric()))
        .ok_or_else(|| anyhow!("unsupported NodeQuality report URL"))?;
    let (signing_ip, timestamp) = signing_identity(app).await?;
    let url = format!("{API}/api/v1/record/{token}");
    let signature = signing_signature(&url, &timestamp, &signing_ip);
    let response = app
        .http
        .get(&url)
        .header(reqwest::header::USER_AGENT, UA)
        .header(reqwest::header::ORIGIN, "https://nodequality.com")
        .header(reqwest::header::REFERER, "https://nodequality.com/")
        .header("x-dynamic-sign-v", signature)
        .header("x-dynamic-sign-t", &timestamp)
        .timeout(Duration::from_secs(20))
        .send()
        .await?
        .error_for_status()?;
    let payload: Value = response.json().await?;
    if payload["success"] != true || payload["data"]["token"] != token {
        return Err(anyhow!("NodeQuality returned an invalid or mismatched report"));
    }
    let encoded = payload["data"]["result"].as_str().ok_or_else(|| anyhow!("report archive missing"))?;
    if encoded.trim().is_empty() {
        return Err(anyhow!("NodeQuality report is empty"));
    }
    let compact = encoded.chars().filter(|c| !c.is_ascii_whitespace()).collect::<String>();
    let compressed = base64::engine::general_purpose::STANDARD.decode(compact)?;
    if compressed.len() > MAX_ZIP {
        return Err(anyhow!("NodeQuality archive exceeds size limit"));
    }
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(compressed))?;
    let mut report = parse_archive(&mut archive)?;
    if file(&report, "ip_quality.log").map(str::is_empty).unwrap_or(true)
        || (file(&report, "net_quality.log").map(str::is_empty).unwrap_or(true)
            && file(&report, "backroute_trace.log").map(str::is_empty).unwrap_or(true))
    {
        report.extend(fetch_report_svgs(app, &report).await?);
    }
    parse_report_archive(report).ok_or_else(|| anyhow!("NodeQuality report fields missing"))
}

fn parse_archive(archive: &mut zip::ZipArchive<std::io::Cursor<Vec<u8>>>) -> Result<HashMap<String, String>> {
    let mut files = HashMap::new();
    for index in 0..archive.len() {
        let file = archive.by_index(index)?;
        if file.is_dir() || file.size() as usize > MAX_JSON {
            continue;
        }
        let name = file.name().to_owned();
        if !name.ends_with(".json") && !name.ends_with(".log") && !name.ends_with(".svg") {
            continue;
        }
        let mut contents = String::with_capacity(file.size() as usize);
        file.take(MAX_JSON as u64 + 1).read_to_string(&mut contents)?;
        if contents.len() <= MAX_JSON {
            files.insert(name, contents);
        }
    }
    Ok(files)
}

fn file<'a>(files: &'a HashMap<String, String>, basename: &str) -> Option<&'a str> {
    files
        .iter()
        .find(|(name, _)| name.as_str() == basename || name.ends_with(&format!("/{basename}")))
        .map(|(_, contents)| contents.as_str())
}

fn parse_report_archive(files: HashMap<String, String>) -> Option<Value> {
    let ip_quality =
        first_ipv4_json(file(&files, "ip_quality.json").unwrap_or_default()).unwrap_or_else(|| json!({}));
    let ip_log = first_ipv4_section(file(&files, "ip_quality.log").unwrap_or_default());
    let net_log = first_ipv4_section(
        file(&files, "backroute_trace.log").or_else(|| file(&files, "net_quality.log")).unwrap_or_default(),
    );

    // If a provider omits the JSON members, the report links embedded in the
    // archive are the supported text fallback. They are restricted to the
    // report host and are never treated as arbitrary URLs.
    let ip_text = if ip_log.is_empty() {
        first_ipv4_section(file(&files, "ip_quality.svg").unwrap_or_default())
    } else {
        ip_log.clone()
    };
    let net_text = if net_log.is_empty() {
        first_ipv4_section(file(&files, "net_quality.svg").unwrap_or_default())
    } else {
        net_log.clone()
    };
    let hardware = first_json(file(&files, "hardware_quality.json").unwrap_or_default())
        .or_else(|| first_json(file(&files, "yabs.json").unwrap_or_default()))
        .unwrap_or_else(|| json!({}));
    let mut result = parse_hardware_quality(&hardware);
    let ip = &ip_quality;
    let media = ip.get("Media").and_then(Value::as_array).and_then(|v| v.first());
    let type_name = ip
        .get("Info")
        .and_then(Value::as_array)
        .and_then(|v| v.first())
        .and_then(|v| v.get("Type"))
        .and_then(Value::as_str)
        .map(clean_text)
        .or_else(|| first_line_value(&ip_text, "IP类型：").map(clean_text));
    let youtube = media.and_then(|v| v.get("Youtube"));
    let chatgpt = media.and_then(|v| v.get("ChatGPT"));
    let port25 = ip
        .get("Mail")
        .and_then(Value::as_array)
        .and_then(|v| v.first())
        .and_then(|v| v.get("Port25"))
        .and_then(Value::as_bool)
        .or_else(|| first_line_value(&ip_text, "本地25端口出站：").map(|v| v == "可用"));
    let route = {
        let route = parse_target_route(&net_text, "广东");
        if route.is_empty() {
            parse_target_route(&net_text, "广州")
        } else {
            route
        }
    };
    let object = result.as_object_mut()?;
    object.insert("ip_type".into(), type_name.map(Value::from).unwrap_or(Value::Null));
    object.insert("youtube".into(), media_unlock(youtube));
    object.insert("chatgpt".into(), media_unlock(chatgpt));
    object.insert("port25".into(), port25.map(Value::from).unwrap_or(Value::Null));
    object.insert("telecom_route".into(), route.get("telecom").cloned().unwrap_or(Value::Null));
    object.insert("unicom_route".into(), route.get("unicom").cloned().unwrap_or(Value::Null));
    object.insert("mobile_route".into(), route.get("mobile").cloned().unwrap_or(Value::Null));
    Some(result)
}

async fn fetch_report_svgs(app: &App, files: &HashMap<String, String>) -> Result<HashMap<String, String>> {
    let mut result = HashMap::new();
    let mut urls = Vec::new();
    for text in files.values() {
        for word in text.split_whitespace() {
            let url = word.trim_matches(|c: char| matches!(c, '(' | ')' | '"' | '\''));
            if let Some(path) = url.strip_prefix("https://Report.Check.Place/") {
                if path.ends_with(".svg")
                    && (path.starts_with("ip/") || path.starts_with("net/"))
                    && !urls.iter().any(|item| item == url)
                {
                    urls.push(url.to_owned());
                }
            }
        }
    }
    for url in urls.into_iter().take(3) {
        let body = app
            .http
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        if body.len() > MAX_JSON {
            continue;
        }
        let text = str::from_utf8(&body).map_err(|_| anyhow!("NodeQuality SVG report is not UTF-8"))?;
        let name = if url.contains("/ip/") { "ip_quality.svg" } else { "net_quality.svg" };
        result.insert(name.to_owned(), svg_to_text(text));
    }
    Ok(result)
}

fn first_ipv4_json(text: &str) -> Option<Value> {
    first_json(text).and_then(|value| {
        if value["Head"]
            .as_array()
            .and_then(|v| v.first())
            .and_then(|v| v["IP"].as_str())
            .map(is_ipv4_label)
            .unwrap_or(false)
        {
            Some(value)
        } else {
            serde_json::Deserializer::from_str(text).into_iter::<Value>().filter_map(Result::ok).find(
                |value| {
                    value["Head"]
                        .as_array()
                        .and_then(|v| v.first())
                        .and_then(|v| v["IP"].as_str())
                        .map(is_ipv4_label)
                        .unwrap_or(false)
                },
            )
        }
    })
}

fn first_json(text: &str) -> Option<Value> {
    serde_json::Deserializer::from_str(text).into_iter::<Value>().filter_map(Result::ok).next()
}

fn is_ipv4_label(value: &str) -> bool {
    value.contains('.') && !value.contains(':')
}

fn first_ipv4_section(text: &str) -> String {
    let mut section = String::new();
    let mut started = false;
    for line in text.replace('\r', "").lines() {
        if line.contains("网络质量体检报告：") || line.contains("IP质量体检报告：") {
            if started {
                break;
            }
            if let Some(ip) = line.split('：').nth(1).and_then(|value| value.split_whitespace().next()) {
                if !is_ipv4_label(ip) {
                    break;
                }
            }
            started = true;
        }
        if started {
            section.push_str(line);
            section.push('\n');
        }
    }
    section
}

fn first_line_value<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.lines().find_map(|line| line.split_once(prefix).map(|(_, value)| value.trim()))
}

fn clean_text(value: &str) -> String {
    strip_ansi(value).split_whitespace().collect::<String>()
}

fn strip_ansi(value: &str) -> String {
    let mut clean = String::with_capacity(value.len());
    let mut escape = false;
    for ch in value.chars() {
        if escape {
            if ch.is_ascii_alphabetic() {
                escape = false;
            }
            continue;
        }
        if ch == '\x1b' {
            escape = true;
            continue;
        }
        clean.push(ch);
    }
    clean
}

fn media_unlock(value: Option<&Value>) -> Value {
    let Some(value) = value else { return Value::Null };
    let status = value["Status"].as_str();
    let region = value["Region"].as_str();
    let kind = value["Type"].as_str();
    match (status, region, kind) {
        (Some(status), Some(region), Some(kind))
            if !status.is_empty() && !region.is_empty() && !kind.is_empty() =>
        {
            Value::String(format!("{status}{region}{kind}"))
        }
        (Some(status), _, _) if !status.is_empty() => Value::String(status.to_owned()),
        _ => Value::Null,
    }
}

fn parse_target_route(text: &str, target: &str) -> HashMap<String, Value> {
    let mut result = HashMap::new();
    let mut current_target = false;
    let mut pending: Option<(&str, &str)> = None;
    for line in text.lines() {
        let clean = strip_ansi(line);
        if clean.contains("回程路由") || clean.contains("回程") {
            current_target = false;
            pending = None;
        }
        if clean.contains(target) {
            current_target = true;
        }
        if !current_target {
            continue;
        }
        for (carrier, key) in [("电信", "telecom"), ("联通", "unicom"), ("移动", "mobile")] {
            if let Some(route) = carrier_route(&clean, carrier) {
                result.insert(key.to_owned(), Value::String(route));
                pending = None;
            } else if clean.contains(carrier) && !result.contains_key(key) {
                pending = Some((carrier, key));
            }
        }
        if let Some((_, key)) = pending {
            if let Some(route) = route_value(&clean) {
                result.insert(key.to_owned(), Value::String(route));
                pending = None;
            }
        }
    }
    result
}

fn carrier_route(line: &str, carrier: &str) -> Option<String> {
    let start = line.find(carrier)?;
    let rest = &line[start + carrier.len()..];
    let end = ["电信", "联通", "移动"].iter().filter_map(|next| rest.find(next)).min().unwrap_or(rest.len());
    route_value(&rest[..end])
}

fn route_value(line: &str) -> Option<String> {
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    if let Some(token) = tokens.iter().find(|token| token.contains("->")) {
        let mut parts = token.split("->");
        let left = parts.next()?.trim();
        let right = parts.next()?.trim();
        if !left.is_empty() && !right.is_empty() {
            return Some(format!("{left}->{right}"));
        }
    }
    let arrow = tokens.iter().position(|token| *token == "->")?;
    let left = tokens.get(arrow.checked_sub(1)?)?;
    let right = tokens.get(arrow + 1)?;
    Some(format!("{left}->{right}"))
}

fn svg_to_text(svg: &str) -> String {
    let mut text = String::with_capacity(svg.len());
    let mut inside = false;
    for ch in svg.chars() {
        match ch {
            '<' => inside = true,
            '>' => {
                inside = false;
                text.push(' ');
            }
            _ if !inside => text.push(ch),
            _ => {}
        }
    }
    text.replace("&gt;", ">").replace("&lt;", "<").replace("&amp;", "&")
}

async fn signing_identity(app: &App) -> Result<(String, String)> {
    let response = app
        .http
        .get(format!("{API}/api/v1/ipinfo"))
        .header(reqwest::header::USER_AGENT, UA)
        .header(reqwest::header::ORIGIN, "https://nodequality.com")
        .timeout(Duration::from_secs(10))
        .send()
        .await?
        .error_for_status()?;
    let info: Value = response.json().await?;
    let ip = info["ip"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("NodeQuality signing identity missing"))?
        .to_owned();
    let timestamp = info["ts"]
        .as_i64()
        .map(|v| v.to_string())
        .ok_or_else(|| anyhow!("NodeQuality signing timestamp missing"))?;
    Ok((ip, timestamp))
}

fn signing_signature(url: &str, timestamp: &str, ip: &str) -> String {
    let source = format!("GET\n\n{url}\n\n{UA}\n\n{ip}{timestamp}\n\n");
    format!("{:x}", Sha1::digest(source.as_bytes()))
}

fn number(object: &Value, path: &[&str]) -> Option<f64> {
    path.iter().try_fold(object, |v, key| v.get(*key))?.as_f64()
}

fn parse_hardware_quality(report: &Value) -> Value {
    let cpu = &report["CPU"]["benchmarks"];
    let disk = &report["Disk"]["benchmarks"]["fio"];
    let yabs_geekbench =
        report["geekbench"].as_array().and_then(|items| items.first()).unwrap_or(&Value::Null);
    json!({
        "single_core": number(cpu, &["sysbench", "single"]),
        "multi_core": number(cpu, &["sysbench", "multi"]),
        "geekbench5_single": number(cpu, &["geekbench5", "single"]).or_else(|| number(yabs_geekbench, &["single"])),
        "geekbench5_multi": number(cpu, &["geekbench5", "multi"]).or_else(|| number(yabs_geekbench, &["multi"])),
        "random4k_single_read_mbps": number(disk, &["randread", "4K_q1", "bw"]).map(|v| v / 1024.0),
        "random4k_single_write_mbps": number(disk, &["randwrite", "4K_q1", "bw"]).map(|v| v / 1024.0),
        "random4k_multi_read_mbps": number(disk, &["randread", "4K_q32", "bw"]).map(|v| v / 1024.0),
        "random4k_multi_write_mbps": number(disk, &["randwrite", "4K_q32", "bw"]).map(|v| v / 1024.0),
        "sequential1m_single_read_mbps": number(disk, &["read", "1M_q1", "bw"]).map(|v| v / 1024.0),
        "sequential1m_single_write_mbps": number(disk, &["write", "1M_q1", "bw"]).map(|v| v / 1024.0),
        "sequential1m_multi_read_mbps": number(disk, &["read", "1M_q8", "bw"]).map(|v| v / 1024.0),
        "sequential1m_multi_write_mbps": number(disk, &["write", "1M_q8", "bw"]).map(|v| v / 1024.0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nq_sysbench_and_fio_values() {
        let report = json!({"CPU":{"benchmarks":{"sysbench":{"single":916.42,"multi":6874.61},"geekbench5":{"single":566,"multi":3575}}},"Disk":{"benchmarks":{"fio":{"randread":{"4K_q1":{"bw":19996},"4K_q32":{"bw":18454}},"randwrite":{"4K_q1":{"bw":15578},"4K_q32":{"bw":14330}},"read":{"1M_q1":{"bw":1146008},"1M_q8":{"bw":1050617}},"write":{"1M_q1":{"bw":1425664},"1M_q8":{"bw":975873}}}}}});
        let parsed = parse_hardware_quality(&report);
        assert_eq!(parsed["single_core"], 916.42);
        assert_eq!(parsed["multi_core"], 6874.61);
        assert_eq!(parsed["geekbench5_single"], 566.0);
        assert_eq!(parsed["geekbench5_multi"], 3575.0);
        assert_eq!(parsed["random4k_multi_read_mbps"], 18454.0 / 1024.0);
        assert_eq!(parsed["sequential1m_multi_write_mbps"], 975873.0 / 1024.0);
    }

    #[test]
    fn allows_missing_report_fields_to_remain_null() {
        let parsed =
            parse_hardware_quality(&json!({"CPU":{"benchmarks":{}},"Disk":{"benchmarks":{"fio":{}}}}));
        assert!(parsed["single_core"].is_null());
        assert!(parsed["random4k_multi_read_mbps"].is_null());
    }

    #[test]
    fn parses_ipv4_network_fields_and_ignores_ipv6_section() {
        let ip = json!({
            "Head": [{"IP": "5.178.*.*"}],
            "Info": [{"Type": "广播IP"}],
            "Media": [{
                "Youtube": {"Status": "解锁", "Region": "NL", "Type": "原生"},
                "ChatGPT": {"Status": "解锁", "Region": "DE", "Type": "原生"}
            }],
            "Mail": [{"Port25": true}]
        });
        let mut files = HashMap::new();
        files.insert("ip_quality.json".into(), format!("{}\n{}", ip, json!({"Head":[{"IP":"2a14:*"}]})));
        files.insert("net_quality.log".into(), "网络质量体检报告：5.178.*.*\n广州TCP：电信 GTT->163 || 联通 GTT->4837 || 移动 Arelion->CMI\n网络质量体检报告：2a14:*\n广州TCP：电信 IPv6->163 || 联通 IPv6->4837 || 移动 IPv6->CMI".into());
        let parsed = parse_report_archive(files).unwrap();
        assert_eq!(parsed["ip_type"], "广播IP");
        assert_eq!(parsed["youtube"], "解锁NL原生");
        assert_eq!(parsed["chatgpt"], "解锁DE原生");
        assert_eq!(parsed["port25"], true);
        assert_eq!(parsed["telecom_route"], "GTT->163");
        assert_eq!(parsed["unicom_route"], "GTT->4837");
        assert_eq!(parsed["mobile_route"], "Arelion->CMI");
    }

    #[tokio::test]
    async fn fetches_the_example_nodequality_report_live() {
        let app = App::for_test(crate::db::Db::open(":memory:").unwrap());
        let report = fetch_benchmark(&app, "https://nodequality.com/r/lBWzg0s3UF7LtfJDcxKdhew4VLGhMvT3")
            .await
            .unwrap();
        assert_eq!(report["geekbench5_single"], 847.0);
        assert_eq!(report["geekbench5_multi"], 1400.0);
        assert_eq!(report["ip_type"], "广播IP");
        assert_eq!(report["youtube"], "解锁NL原生");
        assert_eq!(report["chatgpt"], "解锁DE原生");
        assert_eq!(report["port25"], true);
        assert_eq!(report["telecom_route"], "GTT->163");
        assert_eq!(report["unicom_route"], "GTT->4837");
        assert_eq!(report["mobile_route"], "Arelion->CMI");
    }

    #[test]
    fn signature_is_sha1_hex() {
        let sig = signing_signature("https://api.nodequality.com/api/v1/record/token", "123", "203.0.113.7");
        assert_eq!(sig.len(), 40);
        assert!(sig.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
