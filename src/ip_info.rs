//! Low-rate, IPv4-only IP2Location.io enrichment.

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tracing::warn;

use crate::{db::Node, App};

const TTL: i64 = 7 * 24 * 60 * 60;
const BATCH: usize = 1;

fn query_ipv4(node: &Node) -> Option<Ipv4Addr> {
    let candidate = if !node.ipv4_pin.is_empty() { node.ipv4_pin.as_str() } else { node.ipv4.as_str() };
    let address = candidate.parse::<Ipv4Addr>().ok()?;
    if address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_multicast()
        || address == Ipv4Addr::BROADCAST
    {
        return None;
    }
    Some(address)
}

pub async fn refresh_one(app: &App) -> Result<()> {
    let _guard = app.ip_info_refresh.lock().await;
    let now = chrono::Utc::now().timestamp();
    let pending = app.db.nodes_needing_ip_info(now, TTL, BATCH)?;
    let Some((node_id, _)) = pending.into_iter().find(|(_, ip)| {
        ip.parse::<Ipv4Addr>().is_ok_and(|addr| {
            !addr.is_private()
                && !addr.is_loopback()
                && !addr.is_link_local()
                && !addr.is_unspecified()
                && !addr.is_multicast()
                && addr != Ipv4Addr::BROADCAST
        })
    }) else {
        return Ok(());
    };
    let node = app.db.node(node_id)?.context("node disappeared during IP2Location refresh")?;
    let Some(ipv4) = query_ipv4(&node) else {
        return Ok(());
    };
    refresh_node(app, node_id, ipv4).await
}

pub async fn refresh_all(app: &App) -> Result<usize> {
    let _guard = app.ip_info_refresh.lock().await;
    let nodes = app.db.nodes()?;
    let mut refreshed = 0;
    for node in nodes {
        let Some(ipv4) = query_ipv4(&node) else {
            continue;
        };
        if refresh_node(app, node.id, ipv4).await.is_ok() {
            refreshed += 1;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Ok(refreshed)
}

async fn refresh_node(app: &App, node_id: i64, ipv4: Ipv4Addr) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    let ip = ipv4.to_string();
    let url = format!("https://api.ip2location.io/?ip={ip}");
    let response = app
        .http
        .get(url)
        .header(reqwest::header::USER_AGENT, "monitor-hub/1.5 IP intelligence")
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await;
    let Some(payload) = read_json(response).await else {
        return Ok(());
    };

    let data = normalize(&payload, ipv4, now);
    app.db.save_ip_info_cache(node_id, &ip, now, &data.to_string())?;
    Ok(())
}

async fn read_json(response: Result<reqwest::Response, reqwest::Error>) -> Option<Value> {
    match response {
        Ok(response) if response.status().is_success() => match response.json::<Value>().await {
            Ok(value) if value.get("ip").and_then(Value::as_str).is_some() => Some(value),
            Ok(value) => {
                warn!("IP2Location.io returned an error payload: {value}");
                None
            }
            Err(error) => {
                warn!("IP2Location.io returned invalid JSON: {error}");
                None
            }
        },
        Ok(response) => {
            warn!(status = %response.status(), "IP2Location.io returned a failure status");
            None
        }
        Err(error) => {
            warn!("IP2Location.io request failed: {error}");
            None
        }
    }
}

fn text(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).filter(|v| !v.is_empty()).map(str::to_owned)
}

fn number(value: &Value, key: &str) -> Option<f64> {
    value.get(key).and_then(Value::as_f64)
}

fn normalize(value: &Value, ipv4: Ipv4Addr, checked_at: i64) -> Value {
    let country =
        text(value, "country_name").map(|v| translate_country(&v)).unwrap_or_else(|| "暂不可用".into());
    let region = text(value, "region_name").unwrap_or_else(|| "暂不可用".into());
    let city = text(value, "city_name").unwrap_or_else(|| "暂不可用".into());
    let asn = text(value, "asn").map(|v| format!("AS{v}")).unwrap_or_else(|| "暂不可用".into());
    let organization = text(value, "as").unwrap_or_else(|| "暂不可用".into());
    let is_proxy = value.get("is_proxy").and_then(Value::as_bool);

    json!({
        "数据来源": "IP2Location.io",
        "脱敏IP": format!("{}.{}.{}.*", ipv4.octets()[0], ipv4.octets()[1], ipv4.octets()[2]),
        "自治系统编号": asn,
        "自治系统组织": organization,
        "国家": country,
        "国家代码": text(value, "country_code").unwrap_or_else(|| "暂不可用".into()),
        "地区": region,
        "城市": city,
        "邮政编码": text(value, "zip_code").unwrap_or_else(|| "暂不可用".into()),
        "时区": text(value, "time_zone").map(|v| format!("UTC{v}")).unwrap_or_else(|| "暂不可用".into()),
        "纬度": number(value, "latitude"),
        "经度": number(value, "longitude"),
        "是否代理": is_proxy.map(|v| if v { "是" } else { "否" }).unwrap_or("暂不可用"),
        "查询时间": checked_at
    })
}

fn translate_country(value: &str) -> String {
    match value {
        "United States" | "United States of America" => "美国".into(),
        "United Kingdom" => "英国".into(),
        "Japan" => "日本".into(),
        "Singapore" => "新加坡".into(),
        "Germany" => "德国".into(),
        "France" => "法国".into(),
        "Netherlands" => "荷兰".into(),
        "Canada" => "加拿大".into(),
        "Australia" => "澳大利亚".into(),
        "Hong Kong" => "中国香港".into(),
        "Taiwan" => "中国台湾".into(),
        "China" => "中国".into(),
        "Victoria" => "维多利亚州".into(),
        "Bayern" => "巴伐利亚州".into(),
        "Noord-Holland" => "北荷兰省".into(),
        "Dhaka" => "达卡".into(),
        "Tokyo" => "东京都".into(),
        "England" => "英格兰".into(),
        other => other.to_owned(),
    }
}

pub fn public_cached(app: &App, node_id: i64, node: &Node) -> Option<Value> {
    let ipv4 = query_ipv4(node)?.to_string();
    let (cached_ip, cached_at, data) = app.db.get_ip_info_cache(node_id).ok()??;
    if cached_ip != ipv4 || chrono::Utc::now().timestamp().saturating_sub(cached_at) > TTL {
        return None;
    }
    serde_json::from_str(&data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_ip2location_fields_to_chinese_labels() {
        let value = json!({
            "country_name": "United States of America",
            "country_code": "US",
            "region_name": "Colorado",
            "city_name": "Boulder",
            "zip_code": "80302",
            "time_zone": "-07:00",
            "latitude": 40.01499,
            "longitude": -105.27055,
            "asn": "400619",
            "as": "ArossCloud Inc.",
            "is_proxy": false
        });
        let normalized = normalize(&value, "186.241.72.132".parse().unwrap(), 1);
        assert_eq!(normalized["数据来源"], "IP2Location.io");
        assert_eq!(normalized["脱敏IP"], "186.241.72.*");
        assert_eq!(normalized["自治系统编号"], "AS400619");
        assert_eq!(normalized["国家"], "美国");
        assert_eq!(normalized["是否代理"], "否");
        assert!(!normalized.to_string().contains("186.241.72.132"));
    }

    #[test]
    fn only_selects_real_ipv4_field() {
        let node =
            Node { ipv4: "192.168.100.3".into(), ipv4_pin: "27.154.186.74".into(), ..Default::default() };
        assert_eq!(query_ipv4(&node), Some("27.154.186.74".parse().unwrap()));
        let node = Node { ipv4: "192.168.100.3".into(), ..Default::default() };
        assert_eq!(query_ipv4(&node), None);
        let node = Node { ipv4: "203.0.113.5".into(), ..Default::default() };
        assert_eq!(query_ipv4(&node), Some("203.0.113.5".parse().unwrap()));
    }
}
