use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::Duration;
use tauri::State;
use zeroize::{Zeroize, Zeroizing};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::rngs::OsRng;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};

const BROWSER_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

#[derive(Clone)]
struct RouterSession {
    client: reqwest::Client,
    session_token: String,
}

#[derive(Default)]
struct RouterSessions(Mutex<HashMap<String, RouterSession>>);

#[derive(Serialize)]
struct RouterProbeResult {
    status: u16,
    title: Option<String>,
}

#[derive(Serialize)]
struct RouterLoginResult {
    address: String,
    title: Option<String>,
}

#[derive(Serialize)]
struct RouterRuleResult {
    status: u16,
    confirmed: bool,
    error_code: Option<String>,
}

#[derive(Serialize, Clone)]
struct RouterRule {
    inst_id: String,
    name: String,
    enabled: bool,
    mode: String,
    device_mac: Option<String>,
    domains: Vec<String>,
    schedule: Option<String>,
}

#[derive(Serialize, Clone)]
struct RouterDevice {
    name: String,
    mac: String,
    ip: String,
    last_connection: Option<String>,
}

#[derive(serde::Deserialize)]
struct RouterLoginResponse {
    #[serde(default)]
    login_need_refresh: bool,
    #[serde(rename = "loginErrMsg", default)]
    login_error: String,
    #[serde(rename = "sess_token", default)]
    session_token: Option<String>,
}

#[tauri::command]
fn probe_router(address: String) -> Result<RouterProbeResult, String> {
    let ip: Ipv4Addr = address
        .trim()
        .parse()
        .map_err(|_| "Enter the router's IPv4 address, such as 192.168.1.1".to_string())?;
    if !ip.is_private() {
        return Err("For safety, only private LAN IPv4 addresses are allowed".to_string());
    }

    let endpoint = SocketAddr::from((ip, 80));
    let timeout = Duration::from_secs(3);
    let mut stream = TcpStream::connect_timeout(&endpoint, timeout)
        .map_err(|error| format!("Could not reach {ip}:80: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("Could not configure router connection: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("Could not configure router connection: {error}"))?;

    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: RouterWarden/1.0\r\nConnection: close\r\n\r\n"
    )
    .map_err(|error| format!("Could not send a read-only request to {ip}: {error}"))?;

    let mut response = Vec::with_capacity(8192);
    let mut chunk = [0_u8; 2048];
    while response.len() < 65_536 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => response.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => break,
            Err(error) => return Err(format!("Could not read the router response: {error}")),
        }
    }

    let response = String::from_utf8_lossy(&response);
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| "The router returned an unreadable HTTP response".to_string())?;
    let title = extract_html_title(&response);

    Ok(RouterProbeResult { status, title })
}

#[tauri::command]
async fn connect_router(
    address: String,
    username: String,
    password: String,
    sessions: State<'_, RouterSessions>,
) -> Result<RouterLoginResult, String> {
    let ip: Ipv4Addr = address
        .trim()
        .parse()
        .map_err(|_| "Enter the router's IPv4 address, such as 192.168.1.1".to_string())?;
    let mut password = Zeroizing::new(password);
    if !ip.is_private() {
        return Err("For safety, only private LAN IPv4 addresses are allowed".to_string());
    }
    if username.trim().is_empty() || password.is_empty() {
        return Err("Enter the router username and password".to_string());
    }

    let address = ip.to_string();
    let base_url = format!("http://{address}/");
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .user_agent(BROWSER_USER_AGENT)
        .http1_title_case_headers()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|error| format!("Could not prepare a local router session: {error}"))?;

    let page_response = client
        .get(&base_url)
        .send()
        .await
        .map_err(|error| format!("Could not reach the router: {error}"))?;
    let page_html = page_response
        .text()
        .await
        .map_err(|error| format!("Could not read the router login page: {error}"))?;
    let session_token = extract_input_value(&page_html, "_sessionTOKEN").unwrap_or_default();

    let challenge_response = client
        .get(format!("{base_url}?_type=loginData&_tag=login_token"))
        .send()
        .await
        .map_err(|error| format!("Could not request the router login challenge: {error}"))?;
    let challenge_xml = challenge_response
        .text()
        .await
        .map_err(|error| format!("Could not read the router login challenge: {error}"))?;
    let challenge_document = roxmltree::Document::parse(&challenge_xml)
        .map_err(|_| "The router returned an invalid login challenge".to_string())?;
    let challenge = challenge_document
        .root_element()
        .text()
        .unwrap_or_default()
        .trim()
        .to_string();
    if challenge.is_empty() {
        password.zeroize();
        return Err("The router returned an empty login challenge".to_string());
    }

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    password.zeroize();
    hasher.update(challenge.as_bytes());
    let digest_hex: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let password_hash = Zeroizing::new(digest_hex);

    let login_response = client
        .post(format!("{base_url}?_type=loginData&_tag=login_entry"))
        .form(&[
            ("action", "login"),
            ("Password", password_hash.as_str()),
            ("Username", username.trim()),
            ("_sessionTOKEN", session_token.as_str()),
        ])
        .send()
        .await
        .map_err(|error| format!("Could not submit the router login request: {error}"))?;
    let login_result: RouterLoginResponse = login_response
        .json()
        .await
        .map_err(|_| "The router returned an unreadable login response".to_string())?;
    if !login_result.login_need_refresh {
        let message = login_result.login_error.trim();
        return Err(if message.is_empty() {
            "The router did not confirm login. Check the username and password.".to_string()
        } else {
            message.to_string()
        });
    }
    let login_session_token = login_result
        .session_token
        .filter(|token| !token.is_empty());

    let authenticated_page = client
        .get(&base_url)
        .send()
        .await
        .map_err(|error| format!("Login succeeded, but the router session could not be verified: {error}"))?
        .text()
        .await
        .map_err(|error| format!("Login succeeded, but the router session could not be read: {error}"))?;
    if authenticated_page.contains("Please login") {
        return Err("The router did not retain the login session".to_string());
    }

    let title = extract_document_title(&authenticated_page);
    let session_token = extract_session_token(&authenticated_page)
        .or(login_session_token)
        .ok_or_else(|| "The authenticated router page did not provide a session token".to_string())?;
    sessions
        .0
        .lock()
        .map_err(|_| "Router session storage is unavailable".to_string())?
        .insert(
            address.clone(),
            RouterSession {
                client,
                session_token,
            },
        );

    Ok(RouterLoginResult { address, title })
}

#[tauri::command]
async fn apply_url_blacklist(
    address: String,
    device_mac: String,
    domains: Vec<String>,
    schedule: Option<Schedule>,
    sessions: State<'_, RouterSessions>,
) -> Result<RouterRuleResult, String> {
    let domains = normalize_domains(&domains)?;
    apply_profile(address, device_mac, Some(domains), schedule, &sessions).await
}

#[tauri::command]
async fn apply_internet_block(
    address: String,
    device_mac: String,
    schedule: Option<Schedule>,
    sessions: State<'_, RouterSessions>,
) -> Result<RouterRuleResult, String> {
    apply_profile(address, device_mac, None, schedule, &sessions).await
}

/// Days are 0 = Sunday .. 6 = Saturday; the router needs the end after the start on the same day.
#[derive(serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Schedule {
    days: Vec<u8>,
    start_hour: u8,
    start_min: u8,
    end_hour: u8,
    end_min: u8,
}

impl Schedule {
    fn all_day() -> Self {
        Self {
            days: (0..7).collect(),
            start_hour: 0,
            start_min: 0,
            end_hour: 23,
            end_min: 59,
        }
    }

    // The router's `Week` field is a 7-bit mask in Sun..Sat order, Sunday being the highest bit.
    fn validated_week(&self) -> Result<u8, String> {
        if self.days.is_empty() {
            return Err("Choose at least one day".to_string());
        }
        let mut week = 0_u8;
        for day in &self.days {
            if *day > 6 {
                return Err("Invalid day in schedule".to_string());
            }
            week |= 1 << (6 - day);
        }
        if self.start_hour > 23 || self.end_hour > 23 || self.start_min > 59 || self.end_min > 59 {
            return Err("Invalid time in schedule".to_string());
        }
        let start = u16::from(self.start_hour) * 60 + u16::from(self.start_min);
        let end = u16::from(self.end_hour) * 60 + u16::from(self.end_min);
        if end <= start {
            return Err("The end time must be after the start time on the same day".to_string());
        }
        Ok(week)
    }
}

async fn apply_profile(
    address: String,
    device_mac: String,
    domains: Option<Vec<String>>,
    schedule: Option<Schedule>,
    sessions: &RouterSessions,
) -> Result<RouterRuleResult, String> {
    let schedule = schedule.unwrap_or_else(Schedule::all_day);
    let week = schedule.validated_week()?;
    let ip: Ipv4Addr = address
        .trim()
        .parse()
        .map_err(|_| "Enter the router's IPv4 address".to_string())?;
    if !ip.is_private() {
        return Err("For safety, only private LAN IPv4 addresses are allowed".to_string());
    }
    let device_mac = normalize_mac(&device_mac)?;
    let address = ip.to_string();
    let session = sessions
        .0
        .lock()
        .map_err(|_| "Router session storage is unavailable".to_string())?
        .get(&address)
        .cloned()
        .ok_or_else(|| "Sign in to the router before applying a rule".to_string())?;
    let (session, _) = prepare_parental_controls(&address, sessions, session).await?;

    let suffix = device_mac.replace(':', "");
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let profile_name = router_profile_name(timestamp, &suffix);
    let payload = build_profile_payload(
        &device_mac,
        &profile_name,
        domains.as_deref(),
        (week, &schedule),
        &session.session_token,
    );
    post_parental_controls(&address, &session, payload).await
}

// `domains: None` bans all internet access; the router ignores URL fields in that mode.
fn build_profile_payload(
    device_mac: &str,
    profile_name: &str,
    domains: Option<&[String]>,
    (week, schedule): (u8, &Schedule),
    session_token: &str,
) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("IF_ACTION", "Apply")
        .append_pair("Enable", "1")
        .append_pair("_InstID", "-1")
        .append_pair("ChildId", device_mac)
        .append_pair("Week", &week.to_string())
        .append_pair("Name", profile_name)
        .append_pair("StartHour", &schedule.start_hour.to_string())
        .append_pair("StartMin", &schedule.start_min.to_string())
        .append_pair("EndHour", &schedule.end_hour.to_string())
        .append_pair("EndMin", &schedule.end_min.to_string())
        .append_pair("FilterMode", if domains.is_some() { "BlackList" } else { "NotAllowed" });
    if let Some(domains) = domains {
        for (name, value) in url_blacklist_form_fields(domains) {
            form.append_pair(&name, &value);
        }
    }
    let mut payload = form
        .append_pair("Btn_cancel_ParentCtrl", "")
        .append_pair("Btn_apply_ParentCtrl", "")
        .finish();
    payload.push_str("&_sessionTOKEN=");
    payload.push_str(session_token);
    payload
}

async fn post_parental_controls(
    address: &str,
    session: &RouterSession,
    payload: String,
) -> Result<RouterRuleResult, String> {
    let digest = Sha256::digest(payload.as_bytes());
    let digest_hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let integrity_header = encrypt_integrity_digest(&digest_hex)?;
    let response = session
        .client
        .post(format!(
            "http://{address}/?_type=menuData&_tag=firewall_parentctrl_lua.lua"
        ))
        .header("Check", integrity_header)
        .header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        .header("Accept", "*/*")
        .header("Origin", format!("http://{address}"))
        .header("Referer", format!("http://{address}/"))
        .header("X-Requested-With", "XMLHttpRequest")
        .body(payload)
        .send()
        .await
        .map_err(|error| format!("Could not submit the router request: {error}"))?;
    let status = response.status().as_u16();
    let body = response
        .text()
        .await
        .map_err(|error| format!("Could not read the router response: {error}"))?;
    let result = parse_router_rule_response(&body);
    Ok(RouterRuleResult {
        status,
        confirmed: result.as_ref().is_some_and(|(status, _)| status == "SUCC"),
        error_code: result.and_then(|(status, parameter)| {
            (status != "SUCC").then(|| parameter.unwrap_or(status))
        }),
    })
}

#[tauri::command]
async fn list_router_rules(
    address: String,
    sessions: State<'_, RouterSessions>,
) -> Result<Vec<RouterRule>, String> {
    let ip: Ipv4Addr = address
        .trim()
        .parse()
        .map_err(|_| "Enter the router's IPv4 address".to_string())?;
    if !ip.is_private() {
        return Err("For safety, only private LAN IPv4 addresses are allowed".to_string());
    }
    let address = ip.to_string();
    let session = sessions
        .0
        .lock()
        .map_err(|_| "Router session storage is unavailable".to_string())?
        .get(&address)
        .cloned()
        .ok_or_else(|| "Sign in to the router before loading its rules".to_string())?;
    let (_, data) = prepare_parental_controls(&address, &sessions, session).await?;
    parse_router_rules(&data)
}

#[tauri::command]
async fn delete_router_rule(
    address: String,
    inst_id: String,
    sessions: State<'_, RouterSessions>,
) -> Result<RouterRuleResult, String> {
    let ip: Ipv4Addr = address
        .trim()
        .parse()
        .map_err(|_| "Enter the router's IPv4 address".to_string())?;
    if !ip.is_private() {
        return Err("For safety, only private LAN IPv4 addresses are allowed".to_string());
    }
    let inst_id = inst_id.trim();
    if !is_valid_inst_id(inst_id) {
        return Err("Invalid router rule identifier".to_string());
    }
    let address = ip.to_string();
    let session = sessions
        .0
        .lock()
        .map_err(|_| "Router session storage is unavailable".to_string())?
        .get(&address)
        .cloned()
        .ok_or_else(|| "Sign in to the router before deleting a rule".to_string())?;
    let (session, _) = prepare_parental_controls(&address, &sessions, session).await?;
    let payload = format!(
        "IF_ACTION=Delete&{}&_sessionTOKEN={}",
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("_InstID", inst_id)
            .finish(),
        session.session_token
    );
    post_parental_controls(&address, &session, payload).await
}

fn describe_schedule(fields: &HashMap<String, String>) -> Option<String> {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let number = |key: &str| fields.get(key)?.parse::<u8>().ok();
    let week = number("Week")?;
    let (start_hour, start_min) = (number("StartHour")?, number("StartMin")?);
    let (end_hour, end_min) = (number("EndHour")?, number("EndMin")?);
    let days = if week & 0x7f == 0x7f {
        "Every day".to_string()
    } else {
        (0..7)
            .filter(|day| week & (1 << (6 - day)) != 0)
            .map(|day| DAYS[day as usize])
            .collect::<Vec<_>>()
            .join(", ")
    };
    let time = if (start_hour, start_min, end_hour, end_min) == (0, 0, 23, 59) {
        "all day".to_string()
    } else {
        format!("{start_hour:02}:{start_min:02}-{end_hour:02}:{end_min:02}")
    };
    Some(format!("{days}, {time}"))
}

fn is_valid_inst_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn parse_router_rules(xml: &str) -> Result<Vec<RouterRule>, String> {
    let document = roxmltree::Document::parse(xml)
        .map_err(|error| format!("The router returned an invalid rule-list response: {error}"))?;
    let root = document.root_element();
    let status = root
        .descendants()
        .find(|node| node.has_tag_name("IF_ERRORSTR"))
        .and_then(|node| node.text())
        .map(str::trim)
        .unwrap_or("missing");
    if status != "SUCC" {
        return Err(format!("Router rule request failed (code {status})"));
    }

    let mut rules = Vec::new();
    for instance in root.descendants().filter(|node| node.has_tag_name("Instance")) {
        let mut fields: HashMap<String, String> = HashMap::new();
        let mut children = instance.children().filter(|node| node.is_element()).peekable();
        while let Some(node) = children.next() {
            if node.has_tag_name("ParaName") {
                if let Some(value) = children.next_if(|next| next.has_tag_name("ParaValue")) {
                    fields.insert(
                        node.text().unwrap_or_default().trim().to_string(),
                        value.text().unwrap_or_default().trim().to_string(),
                    );
                }
            }
        }
        let Some(inst_id) = fields.get("_InstID").or_else(|| fields.get("InstID")) else {
            continue;
        };
        let Some(name) = fields.get("Name") else {
            continue;
        };
        let device_mac = instance
            .descendants()
            .filter(|node| node.has_tag_name("ParaValue"))
            .filter_map(|node| normalize_mac(node.text().unwrap_or_default()).ok())
            .next();
        let domains = (0..5)
            .filter_map(|index| fields.get(&format!("URL{index}")))
            .filter(|value| !value.is_empty() && value.as_str() != "NULL")
            .cloned()
            .collect();
        rules.push(RouterRule {
            inst_id: inst_id.clone(),
            name: name.clone(),
            enabled: fields.get("Enable").is_none_or(|value| value == "1"),
            mode: fields.get("FilterMode").cloned().unwrap_or_default(),
            device_mac,
            domains,
            schedule: describe_schedule(&fields),
        });
    }
    Ok(rules)
}

// The router only accepts a rule post after the Parental Controls page and data were loaded.
async fn prepare_parental_controls(
    address: &str,
    sessions: &RouterSessions,
    session: RouterSession,
) -> Result<(RouterSession, String), String> {
    let session = refresh_session(address, sessions, session).await?;
    let page = session
        .client
        .get(format!(
            "http://{address}/?_type=menuView&_tag=parentCtrl&Menu3Location=0"
        ))
        .header("X-Requested-With", "XMLHttpRequest")
        .header("Referer", format!("http://{address}/"))
        .send()
        .await
        .map_err(|error| format!("Could not load the Parental Controls page: {error}"))?
        .text()
        .await
        .map_err(|error| format!("Could not read the Parental Controls page: {error}"))?;
    let session_token = extract_session_token(&page)
        .filter(|token| token.len() >= 16 && token.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        .unwrap_or_else(|| session.session_token.clone());
    let data = session
        .client
        .get(format!(
            "http://{address}/?_type=menuData&_tag=firewall_parentctrl_lua.lua"
        ))
        .header("X-Requested-With", "XMLHttpRequest")
        .header("Referer", format!("http://{address}/"))
        .send()
        .await
        .map_err(|error| format!("Could not load Parental Controls data: {error}"))?
        .text()
        .await
        .map_err(|error| format!("Could not read Parental Controls data: {error}"))?;
    let prepared = RouterSession {
        client: session.client,
        session_token,
    };
    sessions
        .0
        .lock()
        .map_err(|_| "Router session storage is unavailable".to_string())?
        .insert(address.to_string(), prepared.clone());
    Ok((prepared, data))
}

// The router reissues _sessionTmpToken on each page load and drops idle sessions.
async fn refresh_session(
    address: &str,
    sessions: &RouterSessions,
    session: RouterSession,
) -> Result<RouterSession, String> {
    let html = session
        .client
        .get(format!("http://{address}/"))
        .send()
        .await
        .map_err(|error| format!("Could not reach the router: {error}"))?
        .text()
        .await
        .map_err(|error| format!("Could not read the router page: {error}"))?;
    let token = if html.contains("Please login") {
        None
    } else {
        extract_session_token(&html)
    };
    let mut stored = sessions
        .0
        .lock()
        .map_err(|_| "Router session storage is unavailable".to_string())?;
    let Some(session_token) = token else {
        stored.remove(address);
        return Err("The router session expired. Sign in again.".to_string());
    };
    let refreshed = RouterSession {
        client: session.client,
        session_token,
    };
    stored.insert(address.to_string(), refreshed.clone());
    Ok(refreshed)
}

#[tauri::command]
async fn keep_router_session_alive(
    address: String,
    sessions: State<'_, RouterSessions>,
) -> Result<(), String> {
    let ip: Ipv4Addr = address
        .trim()
        .parse()
        .map_err(|_| "Enter the router's IPv4 address".to_string())?;
    let address = ip.to_string();
    let session = sessions
        .0
        .lock()
        .map_err(|_| "Router session storage is unavailable".to_string())?
        .get(&address)
        .cloned()
        .ok_or_else(|| "Not signed in to the router".to_string())?;
    refresh_session(&address, &sessions, session).await.map(|_| ())
}

fn parse_router_rule_response(body: &str) -> Option<(String, Option<String>)> {
    let document = roxmltree::Document::parse(body).ok()?;
    let root = document.root_element();
    let status = root
        .descendants()
        .find(|node| node.has_tag_name("IF_ERRORSTR"))
        .and_then(|node| node.text())
        .map(|code| code.trim().to_string())?;
    let parameter = root
        .descendants()
        .find(|node| node.has_tag_name("IF_ERRORPARAM"))
        .and_then(|node| node.text())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && value != "SUCC");
    Some((status, parameter))
}

#[tauri::command]
async fn list_router_devices(
    address: String,
    sessions: State<'_, RouterSessions>,
) -> Result<Vec<RouterDevice>, String> {
    let ip: Ipv4Addr = address
        .trim()
        .parse()
        .map_err(|_| "Enter the router's IPv4 address".to_string())?;
    if !ip.is_private() {
        return Err("For safety, only private LAN IPv4 addresses are allowed".to_string());
    }
    let address = ip.to_string();
    let session = sessions
        .0
        .lock()
        .map_err(|_| "Router session storage is unavailable".to_string())?
        .get(&address)
        .cloned()
        .ok_or_else(|| "Sign in to the router before refreshing devices".to_string())?;
    let xml = session
        .client
        .get(format!(
            "http://{address}/?_type=menuData&_tag=wlan_homepage_lua.lua&InstNum=32"
        ))
        .send()
        .await
        .map_err(|error| format!("Could not load the router device list: {error}"))?
        .text()
        .await
        .map_err(|error| format!("Could not read the router device list: {error}"))?;
    parse_router_devices(&xml)
}

fn parse_router_devices(xml: &str) -> Result<Vec<RouterDevice>, String> {
    let document = roxmltree::Document::parse(xml)
        .map_err(|error| format!("The router returned an invalid device-list response: {error}"))?;
    let root = document.root_element();
    let error_code = root
        .descendants()
        .find(|node| node.has_tag_name("IF_ERRORPARAM"))
        .and_then(|node| node.text())
        .unwrap_or("missing")
        .trim()
        .to_string();
    if error_code != "SUCC" {
        return Err(format!("Router device request failed (code {error_code})"));
    }
    let access_devices = root
        .descendants()
        .find(|node| node.has_tag_name("OBJ_ACCESSDEV_ID"))
        .ok_or_else(|| {
            let fields = root
                .children()
                .filter(|node| node.is_element())
                .map(|node| node.tag_name().name().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!("Router returned no device list (code {error_code}; fields: {fields})")
        })?;
    let mut devices: Vec<RouterDevice> = Vec::new();

    for instance in access_devices
        .children()
        .filter(|node| node.has_tag_name("Instance"))
    {
        let fields = instance
            .children()
            .filter(|node| node.is_element())
            .collect::<Vec<_>>();
        let mut name = String::new();
        let mut mac_address = String::new();
        let mut ip_address = String::new();
        let mut last_connection = String::new();
        for pair in fields.chunks_exact(2) {
            if !pair[0].has_tag_name("ParaName") || !pair[1].has_tag_name("ParaValue") {
                continue;
            }
            let value = pair[1].text().unwrap_or_default().trim();
            match pair[0].text().unwrap_or_default().trim() {
                "HostName" => name = value.to_string(),
                "MACAddress" => mac_address = value.to_string(),
                "IPAddress" => ip_address = value.to_string(),
                "LastConnection" => last_connection = value.to_string(),
                _ => {}
            }
        }
        let Ok(mac) = normalize_mac(&mac_address) else {
            continue;
        };
        let Ok(client_ip) = ip_address.parse::<Ipv4Addr>() else {
            continue;
        };
        if client_ip.is_unspecified() || client_ip.is_broadcast() {
            continue;
        }
        if !devices.iter().any(|device| device.mac == mac) {
            devices.push(RouterDevice {
                name: if name.is_empty() { "Unnamed device".to_string() } else { name },
                mac,
                ip: client_ip.to_string(),
                last_connection: (!last_connection.is_empty()).then_some(last_connection),
            });
        }
    }

    Ok(devices)
}

fn normalize_mac(mac: &str) -> Result<String, String> {
    let parts = mac.trim().split(':').collect::<Vec<_>>();
    if parts.len() != 6
        || parts.iter().any(|part| {
            part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err("Enter a device MAC address in the format 01:23:45:67:89:AB".to_string());
    }
    Ok(parts.join(":").to_ascii_lowercase())
}

fn normalize_domain(domain: &str) -> Result<String, String> {
    let domain = domain.trim().to_ascii_lowercase();
    if domain.is_empty()
        || domain.len() > 253
        || domain.contains('/')
        || domain.contains(':')
        || domain.contains('*')
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("Enter a plain website domain, such as example.com".to_string());
    }
    Ok(domain)
}

fn normalize_domains(domains: &[String]) -> Result<Vec<String>, String> {
    if domains.is_empty() || domains.len() > 5 {
        return Err("Enter between 1 and 5 website domains".to_string());
    }

    let mut normalized = Vec::with_capacity(domains.len());
    for domain in domains {
        let domain = normalize_domain(domain)?;
        if !normalized.contains(&domain) {
            normalized.push(domain);
        }
    }
    Ok(normalized)
}

fn router_profile_name(timestamp: u64, mac_suffix: &str) -> String {
    format!("R{:07}{}", timestamp % 10_000_000, &mac_suffix[mac_suffix.len() - 2..])
}

fn url_blacklist_form_fields(domains: &[String]) -> Vec<(String, String)> {
    let mut fields = Vec::with_capacity(6);
    fields.push(("URLCnt".to_string(), domains.len().to_string()));
    for index in 0..5 {
        fields.push((
            format!("URL{index}"),
            domains
                .get(index)
                .cloned()
                .unwrap_or_else(|| "NULL".to_string()),
        ));
    }
    fields
}

fn encrypt_integrity_digest(digest_hex: &str) -> Result<String, String> {
    const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwlo/vZBnSJ2MyJ0dbNcw\nDvzPqBN+O/BPvLX93GIJVSZmquJHD9X6Xn6VYeM9mRKzjEbXPlv73Dj/gjjtNj9j\nTq2QVyW2Sd4ZkY9e3h1ALCCCfkbjnmSqedyrcvXriTeW+J65jhBje6lTJbafmC5q\nbGiItjt0OeOkT+Vb4S7hYPSWIjeYYBh+7Y/fg25Rt2a+RgC8dahvJ3ttB1LHXADr\noCm6q7G+lpbRAlpC8jjc0rZdS0c6HcBoYgzW8vxjj2fTuFy3CZZTrpPyTv/C8K6B\nhjTnjRe6ocgFVyQ0RIYfx2hxSJcuauR57OzfMzlgFQv3RAXguDZtuVUFLO2sAiwL\nELph3Acfy9Eh58SHcswZvsOSXY0JNb0XeRM9gxpntLRfM6TB7f9hYtYTDw5oKdyN\nBY+nnEa/IpBUjndGDrSs3Z4BxRbYcJEwkKQZkvw/5TpQYbkD6sTRVSlZPaXSjeCl\n0hsLCttqwJqRZcjbWXrINBYFw8PYE14Xr9BCyPgqocdQh7FgvasVgG6u5mLR1PBZ\no4EFF/LdY0yvMG5rl9egBk1XD/UMayhRtmSQEUzYt3eEWLBbqJB6MbVJ2ygcv5EL\nReDY0SWXw1PIEbHeP51A/MyB6kwSgZwdoQW3JiaPnGHMaE0NqfAYPNiGJLMsmvT/\nrNUI/8iSCW+WvSzx9tByUxsCAwEAAQ==\n-----END PUBLIC KEY-----";
    let public_key = RsaPublicKey::from_public_key_pem(PUBLIC_KEY)
        .map_err(|_| "Could not load the router integrity-check key".to_string())?;
    public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, digest_hex.as_bytes())
        .map(|ciphertext| BASE64.encode(ciphertext))
        .map_err(|_| "Could not generate the router integrity header".to_string())
}

#[tauri::command]
fn disconnect_router(address: String, sessions: State<'_, RouterSessions>) -> Result<(), String> {
    let ip: Ipv4Addr = address
        .trim()
        .parse()
        .map_err(|_| "Enter the router's IPv4 address".to_string())?;
    sessions
        .0
        .lock()
        .map_err(|_| "Router session storage is unavailable".to_string())?
        .remove(&ip.to_string());
    Ok(())
}

fn extract_input_value(html: &str, input_id: &str) -> Option<String> {
    for input in html.split('<').filter(|fragment| fragment.starts_with("input")) {
        let tag = input.split('>').next()?;
        if extract_html_attribute(tag, "id").as_deref() == Some(input_id) {
            return extract_html_attribute(tag, "value");
        }
    }
    None
}

fn extract_session_token(html: &str) -> Option<String> {
    let mut latest_token = None;
    for (position, _) in html.match_indices("_sessionTmpToken") {
        let after_name = &html[position + "_sessionTmpToken".len()..];
        let Some(equals) = after_name.find('=') else {
            continue;
        };
        if after_name[..equals].contains(';') || after_name[..equals].contains('\n') {
            continue;
        }
        let assignment = after_name[equals + 1..].trim_start();
        let Some(token) = decode_quoted_javascript_string(assignment) else {
            continue;
        };
        if !token.is_empty() {
            latest_token = Some(token);
        }
    }
    latest_token.or_else(|| {
        extract_input_value(html, "_sessionTOKEN").filter(|value| !value.is_empty())
    })
}

fn decode_quoted_javascript_string(assignment: &str) -> Option<String> {
    let quote = *assignment.as_bytes().first()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }

    let bytes = assignment.as_bytes();
    let mut decoded = Vec::new();
    let mut index = 1;
    while index < bytes.len() && bytes[index] != quote {
        if bytes[index] == b'\\' && index + 1 < bytes.len() {
            if bytes[index + 1] == b'x' && index + 3 < bytes.len() {
                let high = (bytes[index + 2] as char).to_digit(16)? as u8;
                let low = (bytes[index + 3] as char).to_digit(16)? as u8;
                decoded.push((high << 4) | low);
                index += 4;
            } else {
                decoded.push(bytes[index + 1]);
                index += 2;
            }
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).ok()
}

fn extract_html_attribute(tag: &str, attribute: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let marker = format!("{attribute}={quote}");
        if let Some(start) = tag.find(&marker) {
            let value_start = start + marker.len();
            let value_end = tag[value_start..].find(quote)? + value_start;
            return Some(tag[value_start..value_end].to_string());
        }
    }
    None
}

fn extract_document_title(html: &str) -> Option<String> {
    let lowercase_html = html.to_ascii_lowercase();
    let title_start = lowercase_html.find("<title")?;
    let content_start = lowercase_html[title_start..].find('>')? + title_start + 1;
    let content_end = lowercase_html[content_start..].find("</title>")? + content_start;
    Some(html_escape::decode_html_entities(html[content_start..content_end].trim()).to_string())
}

fn extract_html_title(response: &str) -> Option<String> {
    let body = response.split_once("\r\n\r\n")?.1;
    let lowercase_body = body.to_ascii_lowercase();
    let start = lowercase_body.find("<title")?;
    let title_start = lowercase_body[start..].find('>')? + start + 1;
    let title_end = lowercase_body[title_start..].find("</title>")? + title_start;
    let title = body[title_start..title_end].trim();
    (!title.is_empty()).then(|| title.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(RouterSessions::default())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            probe_router,
            connect_router,
            disconnect_router,
            apply_url_blacklist,
            apply_internet_block,
            list_router_devices,
            keep_router_session_alive,
            list_router_rules,
            delete_router_rule
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::{
        encrypt_integrity_digest, extract_session_token, normalize_domain, normalize_domains,
        normalize_mac, parse_router_devices, parse_router_rule_response, parse_router_rules,
        probe_router, router_profile_name, url_blacklist_form_fields, build_profile_payload,
        Schedule,
    };

    #[test]
    fn normalizes_mac_address_case() {
        assert_eq!(normalize_mac("AA:BB:CC:DD:EE:FF").unwrap(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn rejects_malformed_mac_address() {
        assert!(normalize_mac("not-a-mac").is_err());
        assert!(normalize_mac("AA:BB:CC:DD:EE").is_err());
    }

    #[test]
    fn accepts_plain_website_domain() {
        assert_eq!(normalize_domain("Example.COM").unwrap(), "example.com");
    }

    #[test]
    fn rejects_url_schemes_paths_and_wildcards() {
        assert!(normalize_domain("https://example.com").is_err());
        assert!(normalize_domain("example.com/path").is_err());
        assert!(normalize_domain("*.example.com").is_err());
    }

    #[test]
    fn normalizes_multiple_domains_for_one_profile() {
        assert_eq!(
            normalize_domains(&[
                "YouTube.com".to_string(),
                "youtubei.googleapis.com".to_string(),
                "googlevideo.com".to_string(),
                "ytimg.com".to_string(),
                "youtube.googleapis.com".to_string(),
            ])
            .unwrap(),
            [
                "youtube.com",
                "youtubei.googleapis.com",
                "googlevideo.com",
                "ytimg.com",
                "youtube.googleapis.com",
            ]
        );
    }

    #[test]
    fn rejects_empty_or_more_than_five_domains() {
        assert!(normalize_domains(&[]).is_err());
        assert!(normalize_domains(&[
            "a.example".to_string(),
            "b.example".to_string(),
            "c.example".to_string(),
            "d.example".to_string(),
            "e.example".to_string(),
            "f.example".to_string(),
        ])
        .is_err());
    }

    #[test]
    fn fills_all_router_url_slots_and_pads_unused_slots() {
        assert_eq!(
            url_blacklist_form_fields(&[
                "youtube.com".to_string(),
                "googlevideo.com".to_string(),
            ]),
            [
                ("URLCnt".to_string(), "2".to_string()),
                ("URL0".to_string(), "youtube.com".to_string()),
                ("URL1".to_string(), "googlevideo.com".to_string()),
                ("URL2".to_string(), "NULL".to_string()),
                ("URL3".to_string(), "NULL".to_string()),
                ("URL4".to_string(), "NULL".to_string()),
            ]
        );
    }

    #[test]
    fn parses_router_rule_list() {
        let xml = r#"<ajax_response_xml_root><IF_ERRORSTR>SUCC</IF_ERRORSTR><OBJ_PARENT_CONTROL_ID><Instance><ParaName>_InstID</ParaName><ParaValue>2</ParaValue><ParaName>Name</ParaName><ParaValue>YT_Mobile</ParaValue><ParaName>Enable</ParaName><ParaValue>1</ParaValue><ParaName>FilterMode</ParaName><ParaValue>BlackList</ParaValue><ParaName>URL0</ParaName><ParaValue>youtube.com</ParaValue><ParaName>URL1</ParaName><ParaValue>NULL</ParaValue><ParaName>Week</ParaName><ParaValue>62</ParaValue><ParaName>StartHour</ParaName><ParaValue>22</ParaValue><ParaName>StartMin</ParaName><ParaValue>0</ParaValue><ParaName>EndHour</ParaName><ParaValue>23</ParaValue><ParaName>EndMin</ParaName><ParaValue>30</ParaValue><ParaName>ChildId</ParaName><ParaValue>76:7B:FA:61:C3:DE</ParaValue></Instance></OBJ_PARENT_CONTROL_ID></ajax_response_xml_root>"#;
        let rules = parse_router_rules(xml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].inst_id, "2");
        assert_eq!(rules[0].name, "YT_Mobile");
        assert_eq!(rules[0].domains, ["youtube.com"]);
        assert_eq!(rules[0].schedule.as_deref(), Some("Mon, Tue, Wed, Thu, Fri, 22:00-23:30"));
        assert_eq!(rules[0].device_mac.as_deref(), Some("76:7b:fa:61:c3:de"));
    }

    #[test]
    fn internet_block_uses_not_allowed_mode_without_url_fields() {
        let schedule = Schedule::all_day();
        let payload = build_profile_payload(
            "76:7b:fa:61:c3:de",
            "R1234567de",
            None,
            (127, &schedule),
            "tok",
        );
        assert!(payload.contains("FilterMode=NotAllowed"));
        assert!(payload.contains("Week=127&"));
        assert!(payload.contains("EndHour=23&EndMin=59"));
        assert!(!payload.contains("URL"));
        assert!(payload.ends_with("&_sessionTOKEN=tok"));
    }

    #[test]
    fn url_blacklist_payload_keeps_url_fields() {
        let schedule = Schedule::all_day();
        let payload = build_profile_payload(
            "76:7b:fa:61:c3:de",
            "R1234567de",
            Some(&["youtube.com".to_string()]),
            (127, &schedule),
            "tok",
        );
        assert!(payload.contains("FilterMode=BlackList"));
        assert!(payload.contains("URLCnt=1&URL0=youtube.com&URL1=NULL"));
    }

    #[test]
    fn schedule_week_mask_puts_sunday_in_the_highest_bit() {
        let weekdays = Schedule {
            days: vec![1, 2, 3, 4, 5],
            start_hour: 22,
            start_min: 0,
            end_hour: 23,
            end_min: 30,
        };
        assert_eq!(weekdays.validated_week().unwrap(), 0b0111110);
        let sunday_only = Schedule { days: vec![0], ..weekdays.clone() };
        assert_eq!(sunday_only.validated_week().unwrap(), 0b1000000);
        assert_eq!(Schedule::all_day().validated_week().unwrap(), 127);
    }

    #[test]
    fn schedule_rejects_bad_days_and_times() {
        let base = Schedule::all_day();
        assert!(Schedule { days: vec![], ..base.clone() }.validated_week().is_err());
        assert!(Schedule { days: vec![7], ..base.clone() }.validated_week().is_err());
        assert!(Schedule { start_hour: 24, ..base.clone() }.validated_week().is_err());
        assert!(Schedule { start_hour: 20, end_hour: 8, ..base.clone() }.validated_week().is_err());
        assert!(Schedule { start_hour: 9, end_hour: 9, start_min: 0, end_min: 0, ..base }.validated_week().is_err());
    }

    #[test]
    fn rule_list_reports_router_errors() {
        assert!(parse_router_rules("<r><IF_ERRORSTR>SessionTimeout</IF_ERRORSTR></r>").is_err());
    }

    #[test]
    fn generated_router_profile_name_fits_ten_character_limit() {
        let name = router_profile_name(1_234_567_890, "aabbccddeeff");
        assert_eq!(name, "R4567890ff");
        assert!(name.len() <= 10);
    }

    #[test]
    fn loads_router_integrity_key() {
        let header = encrypt_integrity_digest(&"a".repeat(64)).unwrap();
        assert!(!header.is_empty());
    }

    #[test]
    fn parses_router_rule_success_and_error_codes() {
        assert_eq!(
            parse_router_rule_response("<ajax_response_xml_root><IF_ERRORSTR>SUCC</IF_ERRORSTR><IF_ERRORPARAM>SUCC</IF_ERRORPARAM></ajax_response_xml_root>"),
            Some(("SUCC".to_string(), None))
        );
        assert_eq!(
            parse_router_rule_response("<ajax_response_xml_root><IF_ERRORSTR>FAIL</IF_ERRORSTR><IF_ERRORPARAM>FilterMode</IF_ERRORPARAM></ajax_response_xml_root>"),
            Some(("FAIL".to_string(), Some("FilterMode".to_string())))
        );
        assert_eq!(parse_router_rule_response("login page"), None);
    }

    #[test]
    fn extracts_hex_escaped_session_token() {
        assert_eq!(
            extract_session_token(r#"<script>var _sessionTmpToken = "\x61\x62\x31";</script>"#),
            Some("ab1".to_string())
        );
    }

    #[test]
    fn prefers_apply_token_over_login_form_token() {
        let html = r#"<input id="_sessionTOKEN" value="login-token"><script>var _sessionTmpToken = "\x61\x70\x70\x6c\x79";</script>"#;
        assert_eq!(extract_session_token(html), Some("apply".to_string()));
    }

    #[test]
    fn parses_router_xml_devices_and_skips_invalid_rows() {
        let xml = r#"<ajax_response_xml_root><IF_ERRORPARAM>SUCC</IF_ERRORPARAM><OBJ_ACCESSDEV_ID><Instance><ParaName>HostName</ParaName><ParaValue>Office laptop</ParaValue><ParaName>IPAddress</ParaName><ParaValue>192.168.1.24</ParaValue><ParaName>MACAddress</ParaName><ParaValue>AA:BB:CC:DD:EE:FF</ParaValue><ParaName>LastConnection</ParaName><ParaValue>2026-10-23 15:45:00</ParaValue></Instance><Instance><ParaName>HostName</ParaName><ParaValue>Bad client</ParaValue><ParaName>IPAddress</ParaName><ParaValue>bad-ip</ParaValue><ParaName>MACAddress</ParaName><ParaValue>not-a-mac</ParaValue></Instance></OBJ_ACCESSDEV_ID></ajax_response_xml_root>"#;
        let devices = parse_router_devices(xml).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "Office laptop");
        assert_eq!(devices[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(devices[0].ip, "192.168.1.24");
        assert_eq!(devices[0].last_connection.as_deref(), Some("2026-10-23 15:45:00"));
    }

    #[test]
    fn reports_missing_router_device_list_instead_of_empty_devices() {
        assert!(parse_router_devices("<ajax_response_xml_root/>").is_err());
    }

    #[test]
    #[ignore = "requires the local ZTE router at 192.168.1.1"]
    fn probes_local_router_http_page() {
        let result = probe_router("192.168.1.1".to_string()).unwrap();
        assert_eq!(result.status, 200);
    }
}
