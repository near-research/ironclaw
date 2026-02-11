// Discourse API responses include many fields we don't use.
#![allow(dead_code)]

//! Discourse forum channel for IronClaw.
//!
//! This WASM component implements the channel interface for interacting with
//! Discourse forums via direct API polling and posting.
//!
//! # Architecture
//!
//! Polling-first: the agent polls `/posts.json` for new posts, processes them,
//! and replies via `POST /posts.json`. Webhooks are supported as an optional
//! accelerator but not required.
//!
//! # Features
//!
//! - Polling-based post receiving via `/posts.json` with offset tracking
//! - Webhook support (optional, `post_created` / `post_edited`)
//! - Thread mapping: `topic_id` → `discourse:topic:<id>`
//! - Loop prevention: bot username check + marker token detection + whisper filter
//! - Per-persona impersonation via `post_as` metadata field
//! - Response truncation for Discourse's 32K post limit
//!
//! # Security
//!
//! - `Api-Key` and `Api-Username` headers injected by host (WASM never sees credentials)
//! - Webhook secret validated by host via `X-Webhook-Secret` header (when webhooks enabled)
//! - Discourse HMAC (`X-Discourse-Event-Signature`) validated by upstream gateway

// Generate bindings from the WIT file
wit_bindgen::generate!({
    world: "sandboxed-channel",
    path: "../../wit/channel.wit",
});

use serde::{Deserialize, Serialize};

// Re-export generated types
use exports::near::agent::channel::{
    AgentResponse, ChannelConfig, Guest, HttpEndpointConfig, IncomingHttpRequest,
    OutgoingHttpResponse, PollConfig, StatusUpdate,
};
use near::agent::channel_host::{self, EmittedMessage};

// ============================================================================
// Discourse API Types
// ============================================================================

/// Discourse webhook payload for post events.
#[derive(Debug, Deserialize)]
struct DiscoursePostPayload {
    post: DiscoursePost,
}

/// A Discourse post from the webhook payload.
#[derive(Debug, Deserialize)]
struct DiscoursePost {
    /// Unique post identifier.
    id: i64,

    /// Topic this post belongs to.
    topic_id: i64,

    /// Author username.
    username: String,

    /// Raw markdown content.
    raw: String,

    /// Rendered HTML content.
    cooked: String,

    /// Position within the topic (1 = original post).
    post_number: i64,

    /// Post number this is replying to (if any).
    reply_to_post_number: Option<i64>,

    /// Topic URL slug.
    topic_slug: Option<String>,

    /// Topic title.
    topic_title: Option<String>,

    /// ISO 8601 creation timestamp.
    created_at: String,

    /// Category ID.
    #[serde(default)]
    category_id: Option<i64>,

    /// Post type: 1 = regular, 4 = whisper. Best-effort filter.
    #[serde(default)]
    post_type: Option<i64>,
}

/// Discourse `/posts.json` response containing latest posts.
#[derive(Debug, Deserialize)]
struct DiscourseLatestPostsResponse {
    latest_posts: Vec<DiscoursePost>,
}

/// Discourse API response for creating a post.
#[derive(Debug, Deserialize)]
struct DiscourseCreatePostResponse {
    /// Created post ID.
    id: Option<i64>,

    /// Created post number.
    post_number: Option<i64>,

    /// Errors from the API.
    #[serde(default)]
    errors: Option<Vec<String>>,

    /// Error type identifier.
    #[serde(default)]
    error_type: Option<String>,
}

// ============================================================================
// Channel Metadata
// ============================================================================

/// Metadata stored with emitted messages for response routing.
#[derive(Debug, Serialize, Deserialize)]
struct DiscourseMessageMetadata {
    /// Topic ID (primary routing key).
    topic_id: i64,

    /// Post ID that triggered this message.
    post_id: i64,

    /// Post number within the topic (for `reply_to_post_number`).
    post_number: i64,

    /// Username who posted.
    username: String,

    /// Topic title (for context in agent responses).
    topic_title: Option<String>,

    /// Topic slug (for constructing URLs).
    topic_slug: Option<String>,

    /// Category ID.
    category_id: Option<i64>,

    /// Optional: override `Api-Username` for per-persona posting.
    #[serde(default)]
    post_as: Option<String>,
}

// ============================================================================
// Configuration
// ============================================================================

/// Channel configuration from capabilities file.
/// The host injects runtime values like `tunnel_url` and `webhook_secret`.
/// The channel checks `tunnel_url` to auto-switch between webhook and polling mode.
#[derive(Debug, Deserialize)]
struct DiscourseConfig {
    /// Base URL of the Discourse instance (e.g., "https://community.example.com").
    /// Required -- `on_start` errors if missing.
    base_url: Option<String>,

    /// Bot username for loop prevention. Posts from this user are ignored.
    #[serde(default)]
    bot_username: Option<String>,

    /// Marker token embedded in replies for loop detection. Default: "[ironclaw]".
    #[serde(default = "default_marker_token")]
    marker_token: String,

    /// Whether to process `post_edited` webhook events. Default: false.
    #[serde(default)]
    handle_edited_posts: bool,

    /// Category IDs to restrict to. Empty = all categories (default).
    #[serde(default)]
    allowed_categories: Vec<i64>,

    /// If set, only posts from this username are processed. Default: null (all users).
    #[serde(default)]
    owner_username: Option<String>,

    /// Tunnel URL injected by host if user configured a tunnel (ngrok, cloudflare, etc.).
    /// When present, channel uses webhook mode. When absent, uses polling mode.
    #[serde(default)]
    tunnel_url: Option<String>,

    /// Webhook secret injected by host from secrets store.
    #[serde(default)]
    webhook_secret: Option<String>,
}

fn default_marker_token() -> String {
    "[ironclaw]".to_string()
}

// ============================================================================
// Workspace Paths
// ============================================================================

/// Workspace path for persisting base URL across callbacks.
const CONFIG_BASE_URL_PATH: &str = "state/base_url";

/// Workspace path for persisting bot username across callbacks.
const CONFIG_BOT_USERNAME_PATH: &str = "state/bot_username";

/// Workspace path for persisting marker token across callbacks.
const CONFIG_MARKER_TOKEN_PATH: &str = "state/marker_token";

/// Workspace path for persisting handle_edited_posts flag.
const CONFIG_HANDLE_EDITED_PATH: &str = "state/handle_edited_posts";

/// Workspace path for persisting owner_username.
const CONFIG_OWNER_USERNAME_PATH: &str = "state/owner_username";

/// Workspace path for persisting allowed_categories.
const CONFIG_ALLOWED_CATEGORIES_PATH: &str = "state/allowed_categories";

/// Workspace path for tracking the last polled post ID.
const POLL_LAST_POST_ID_PATH: &str = "state/last_post_id";

/// Maximum post content length (Discourse default max is ~32K).
const MAX_POST_LENGTH: usize = 30000;

// ============================================================================
// Channel Implementation
// ============================================================================

struct DiscourseChannel;

impl Guest for DiscourseChannel {
    fn on_start(config_json: String) -> Result<ChannelConfig, String> {
        let config: DiscourseConfig = serde_json::from_str(&config_json)
            .map_err(|e| format!("Failed to parse config: {}", e))?;

        // base_url is required
        let base_url = config
            .base_url
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or("base_url is required in config")?;

        let normalized_url = base_url.trim_end_matches('/');

        // Mode is determined by whether the host injected a tunnel_url.
        // If tunnel is configured, use webhooks. Otherwise, use polling.
        let webhook_mode = config.tunnel_url.is_some();

        if webhook_mode {
            channel_host::log(
                channel_host::LogLevel::Info,
                &format!(
                    "Discourse channel starting in webhook mode (base_url: {})",
                    normalized_url
                ),
            );
        } else {
            channel_host::log(
                channel_host::LogLevel::Info,
                &format!(
                    "Discourse channel starting in polling mode (base_url: {})",
                    normalized_url
                ),
            );
        }

        // Persist config values to workspace (fresh WASM instance per callback)
        let _ = channel_host::workspace_write(CONFIG_BASE_URL_PATH, normalized_url);

        if let Some(ref username) = config.bot_username {
            let _ = channel_host::workspace_write(CONFIG_BOT_USERNAME_PATH, username);
            channel_host::log(
                channel_host::LogLevel::Info,
                &format!("Bot username: {}", username),
            );
        } else {
            channel_host::log(
                channel_host::LogLevel::Warn,
                "bot_username not configured -- loop prevention relies on marker token only",
            );
            let _ = channel_host::workspace_write(CONFIG_BOT_USERNAME_PATH, "");
        }

        let _ = channel_host::workspace_write(CONFIG_MARKER_TOKEN_PATH, &config.marker_token);
        let _ = channel_host::workspace_write(
            CONFIG_HANDLE_EDITED_PATH,
            if config.handle_edited_posts {
                "true"
            } else {
                "false"
            },
        );

        if let Some(ref owner) = config.owner_username {
            let _ = channel_host::workspace_write(CONFIG_OWNER_USERNAME_PATH, owner);
        } else {
            let _ = channel_host::workspace_write(CONFIG_OWNER_USERNAME_PATH, "");
        }

        if !config.allowed_categories.is_empty() {
            let cats_json = serde_json::to_string(&config.allowed_categories)
                .unwrap_or_else(|_| "[]".to_string());
            let _ = channel_host::workspace_write(CONFIG_ALLOWED_CATEGORIES_PATH, &cats_json);
        } else {
            let _ = channel_host::workspace_write(CONFIG_ALLOWED_CATEGORIES_PATH, "[]");
        }

        // Polling when no tunnel, webhooks when tunnel is configured
        let poll = if !webhook_mode {
            Some(PollConfig {
                interval_ms: 30_000, // Poll every 30 seconds
                enabled: true,
            })
        } else {
            None
        };

        Ok(ChannelConfig {
            display_name: "Discourse".to_string(),
            http_endpoints: vec![HttpEndpointConfig {
                path: "/webhook/discourse".to_string(),
                methods: vec!["POST".to_string()],
                require_secret: true,
            }],
            poll,
        })
    }

    fn on_http_request(req: IncomingHttpRequest) -> OutgoingHttpResponse {
        // Defense in depth: if secret validation failed, don't process
        if !req.secret_validated {
            channel_host::log(
                channel_host::LogLevel::Warn,
                "Webhook request with invalid or missing secret -- ignoring",
            );
            return json_response(200, serde_json::json!({"ok": true}));
        }

        // Parse the request body as UTF-8
        let body_str = match std::str::from_utf8(&req.body) {
            Ok(s) => s,
            Err(_) => {
                channel_host::log(
                    channel_host::LogLevel::Warn,
                    "Webhook body is not valid UTF-8 -- ignoring",
                );
                return json_response(200, serde_json::json!({"ok": true}));
            }
        };

        // Extract Discourse event headers
        let event_type = extract_header(&req.headers_json, "X-Discourse-Event-Type");
        let event_name = extract_header(&req.headers_json, "X-Discourse-Event");

        channel_host::log(
            channel_host::LogLevel::Debug,
            &format!(
                "Discourse webhook: type={:?} event={:?}",
                event_type, event_name
            ),
        );

        // Route by event type
        match (event_type.as_deref(), event_name.as_deref()) {
            (Some("post"), Some("post_created")) => {
                handle_post(body_str);
            }
            (Some("post"), Some("post_edited")) => {
                let handle_edits = channel_host::workspace_read(CONFIG_HANDLE_EDITED_PATH)
                    .map(|v| v == "true")
                    .unwrap_or(false);

                if handle_edits {
                    handle_post(body_str);
                } else {
                    channel_host::log(
                        channel_host::LogLevel::Debug,
                        "Ignoring post_edited (disabled in config)",
                    );
                }
            }
            (Some("topic"), Some("topic_created")) => {
                // Don't emit -- first post arrives as post_created
                channel_host::log(
                    channel_host::LogLevel::Debug,
                    "Ignoring topic_created (waiting for post_created)",
                );
            }
            _ => {
                channel_host::log(
                    channel_host::LogLevel::Debug,
                    &format!(
                        "Ignoring Discourse event: type={:?} event={:?}",
                        event_type, event_name
                    ),
                );
            }
        }

        // Always return 200 to prevent Discourse retry storms
        json_response(200, serde_json::json!({"ok": true}))
    }

    fn on_poll() {
        let base_url = match channel_host::workspace_read(CONFIG_BASE_URL_PATH) {
            Some(url) if !url.is_empty() => url,
            _ => {
                channel_host::log(
                    channel_host::LogLevel::Error,
                    "on_poll: base_url not set in workspace",
                );
                return;
            }
        };

        // Read last seen post ID
        let last_post_id: i64 = channel_host::workspace_read(POLL_LAST_POST_ID_PATH)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Fetch latest posts from Discourse.
        // NOTE: /posts.json returns the latest ~30 posts. If more than 30 posts
        // are created between poll intervals, some may be missed. At 30s intervals
        // this requires >60 posts/minute sustained, which is unlikely on most forums.
        // For high-traffic forums, reduce the poll interval or use webhook mode.
        let url = format!("{}/posts.json", base_url);
        let headers = serde_json::json!({
            "Accept": "application/json",
            "Api-Key": "{DISCOURSE_API_KEY}",
            "Api-Username": "{DISCOURSE_API_USERNAME}"
        });

        let response = match channel_host::http_request("GET", &url, &headers.to_string(), None) {
            Ok(r) => r,
            Err(e) => {
                channel_host::log(
                    channel_host::LogLevel::Error,
                    &format!("on_poll: HTTP request failed: {}", e),
                );
                return;
            }
        };

        if response.status != 200 {
            channel_host::log(
                channel_host::LogLevel::Warn,
                &format!("on_poll: Discourse returned status {}", response.status),
            );
            return;
        }

        let api_response: DiscourseLatestPostsResponse =
            match serde_json::from_slice(&response.body) {
                Ok(r) => r,
                Err(e) => {
                    channel_host::log(
                        channel_host::LogLevel::Error,
                        &format!("on_poll: Failed to parse /posts.json: {}", e),
                    );
                    return;
                }
            };

        // First-poll bootstrap: seed high-water mark without emitting historical posts
        if last_post_id == 0 {
            if let Some(max_id) = api_response.latest_posts.iter().map(|p| p.id).max() {
                channel_host::log(
                    channel_host::LogLevel::Info,
                    &format!("on_poll: first run, seeding last_post_id to {}", max_id),
                );
                let _ = channel_host::workspace_write(POLL_LAST_POST_ID_PATH, &max_id.to_string());
            }
            return;
        }

        // Filter to only new posts (id > last_post_id), process oldest first
        let mut new_posts: Vec<&DiscoursePost> = api_response
            .latest_posts
            .iter()
            .filter(|p| p.id > last_post_id)
            .collect();
        new_posts.sort_by_key(|p| p.id);

        if new_posts.is_empty() {
            return;
        }

        channel_host::log(
            channel_host::LogLevel::Debug,
            &format!(
                "on_poll: {} new posts since id {}",
                new_posts.len(),
                last_post_id
            ),
        );

        let mut max_id = last_post_id;

        for post in &new_posts {
            if post.id > max_id {
                max_id = post.id;
            }
            process_post(post);
        }

        // Persist new high-water mark
        if max_id > last_post_id {
            let _ = channel_host::workspace_write(POLL_LAST_POST_ID_PATH, &max_id.to_string());
        }
    }

    fn on_respond(response: AgentResponse) -> Result<(), String> {
        // Parse metadata to get routing info
        let metadata: DiscourseMessageMetadata = serde_json::from_str(&response.metadata_json)
            .map_err(|e| format!("Failed to parse metadata: {}", e))?;

        // Read base_url from workspace
        let base_url = channel_host::workspace_read(CONFIG_BASE_URL_PATH)
            .filter(|s| !s.is_empty())
            .ok_or("base_url not set in workspace")?;

        // Read marker token
        let marker_token = channel_host::workspace_read(CONFIG_MARKER_TOKEN_PATH)
            .unwrap_or_else(|| "[ironclaw]".to_string());

        // Truncate if needed (char-boundary safe to avoid panicking on multi-byte chars)
        let content = if response.content.len() > MAX_POST_LENGTH {
            let mut end = MAX_POST_LENGTH;
            while !response.content.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}\n\n*(Response truncated)*", &response.content[..end])
        } else {
            response.content.clone()
        };

        // Build reply payload with marker footer
        let raw = format!("{}\n\n---\n{}", content, marker_token);

        let payload = serde_json::json!({
            "topic_id": metadata.topic_id,
            "raw": raw,
            "reply_to_post_number": metadata.post_number,
        });

        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| format!("Failed to serialize payload: {}", e))?;

        // Build headers with credential placeholders (host replaces {DISCOURSE_API_KEY} etc.)
        let mut headers = serde_json::json!({
            "Content-Type": "application/json",
            "Api-Key": "{DISCOURSE_API_KEY}",
            "Api-Username": "{DISCOURSE_API_USERNAME}"
        });

        // Per-persona impersonation: override Api-Username if post_as is set
        if let Some(ref persona) = metadata.post_as {
            headers["Api-Username"] = serde_json::Value::String(persona.clone());
            channel_host::log(
                channel_host::LogLevel::Debug,
                &format!("Posting as persona: {}", persona),
            );
        }

        let api_url = format!("{}/posts.json", base_url);

        let result = channel_host::http_request(
            "POST",
            &api_url,
            &headers.to_string(),
            Some(&payload_bytes),
        );

        match result {
            Ok(http_response) => {
                if http_response.status != 200 {
                    let body_preview = String::from_utf8_lossy(&http_response.body);
                    let mut end = body_preview.len().min(200);
                    while end > 0 && !body_preview.is_char_boundary(end) {
                        end -= 1;
                    }
                    return Err(format!(
                        "Discourse API returned status {}: {}",
                        http_response.status,
                        &body_preview[..end]
                    ));
                }

                let api_response: DiscourseCreatePostResponse =
                    serde_json::from_slice(&http_response.body)
                        .map_err(|e| format!("Failed to parse Discourse response: {}", e))?;

                if let Some(errors) = api_response.errors {
                    if !errors.is_empty() {
                        return Err(format!("Discourse API errors: {}", errors.join(", ")));
                    }
                }

                channel_host::log(
                    channel_host::LogLevel::Debug,
                    &format!(
                        "Posted reply to topic {} (post_id={:?}, post_number={:?})",
                        metadata.topic_id, api_response.id, api_response.post_number
                    ),
                );

                Ok(())
            }
            Err(e) => Err(format!("HTTP request failed: {}", e)),
        }
    }

    fn on_status(_update: StatusUpdate) {
        // Discourse has no typing indicator equivalent.
    }

    fn on_shutdown() {
        channel_host::log(
            channel_host::LogLevel::Info,
            "Discourse channel shutting down",
        );
    }
}

// ============================================================================
// Post Handling
// ============================================================================

/// Handle a Discourse post from a webhook (parses `{"post": ...}` envelope).
fn handle_post(body_str: &str) {
    let payload: DiscoursePostPayload = match serde_json::from_str(body_str) {
        Ok(p) => p,
        Err(e) => {
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!("Failed to parse Discourse post payload: {}", e),
            );
            return;
        }
    };

    process_post(&payload.post);
}

/// Process a single Discourse post: apply filters and emit if applicable.
/// Used by both webhook (`handle_post`) and polling (`on_poll`) paths.
fn process_post(post: &DiscoursePost) {
    // --- Loop prevention ---

    // Check bot username
    if let Some(bot_username) = channel_host::workspace_read(CONFIG_BOT_USERNAME_PATH) {
        if !bot_username.is_empty() && post.username == bot_username {
            channel_host::log(
                channel_host::LogLevel::Debug,
                &format!("Ignoring post from bot user: {}", post.username),
            );
            return;
        }
    }

    // Check marker token
    if let Some(marker_token) = channel_host::workspace_read(CONFIG_MARKER_TOKEN_PATH) {
        if !marker_token.is_empty() && post.raw.contains(&marker_token) {
            channel_host::log(
                channel_host::LogLevel::Debug,
                "Ignoring post containing marker token",
            );
            return;
        }
    }

    // Best-effort whisper filter (post_type 4 = whisper)
    if post.post_type == Some(4) {
        channel_host::log(
            channel_host::LogLevel::Debug,
            "Ignoring whisper post (post_type=4)",
        );
        return;
    }

    // --- Optional filters ---

    // Owner filter
    if let Some(owner_username) = channel_host::workspace_read(CONFIG_OWNER_USERNAME_PATH) {
        if !owner_username.is_empty() && post.username != owner_username {
            channel_host::log(
                channel_host::LogLevel::Debug,
                &format!(
                    "Ignoring post from non-owner user: {} (owner: {})",
                    post.username, owner_username
                ),
            );
            return;
        }
    }

    // Category filter
    if let Some(cats_json) = channel_host::workspace_read(CONFIG_ALLOWED_CATEGORIES_PATH) {
        if let Ok(allowed) = serde_json::from_str::<Vec<i64>>(&cats_json) {
            if !allowed.is_empty() {
                if let Some(cat_id) = post.category_id {
                    if !allowed.contains(&cat_id) {
                        channel_host::log(
                            channel_host::LogLevel::Debug,
                            &format!(
                                "Ignoring post from category {} (not in allowed list)",
                                cat_id
                            ),
                        );
                        return;
                    }
                }
                // If post has no category_id and filter is set, skip it
                if post.category_id.is_none() {
                    channel_host::log(
                        channel_host::LogLevel::Debug,
                        "Ignoring post with no category (category filter active)",
                    );
                    return;
                }
            }
        }
    }

    // --- Emit message ---

    let metadata = DiscourseMessageMetadata {
        topic_id: post.topic_id,
        post_id: post.id,
        post_number: post.post_number,
        username: post.username.clone(),
        topic_title: post.topic_title.clone(),
        topic_slug: post.topic_slug.clone(),
        category_id: post.category_id,
        post_as: None,
    };

    let metadata_json = serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".to_string());

    let thread_id = format!("discourse:topic:{}", post.topic_id);

    channel_host::emit_message(&EmittedMessage {
        user_id: post.username.clone(),
        user_name: Some(post.username.clone()),
        content: post.raw.clone(),
        thread_id: Some(thread_id),
        metadata_json,
    });

    channel_host::log(
        channel_host::LogLevel::Debug,
        &format!(
            "Emitted message from {} in topic {} (post #{})",
            post.username, post.topic_id, post.post_number
        ),
    );
}

// ============================================================================
// Utilities
// ============================================================================

/// Extract a header value from the headers JSON string (case-insensitive).
fn extract_header(headers_json: &str, name: &str) -> Option<String> {
    let headers: serde_json::Value = serde_json::from_str(headers_json).ok()?;
    let lower_name = name.to_lowercase();
    if let Some(obj) = headers.as_object() {
        for (key, value) in obj {
            if key.to_lowercase() == lower_name {
                return value.as_str().map(|s| s.to_string());
            }
        }
    }
    None
}

/// Create a JSON HTTP response.
fn json_response(status: u16, value: serde_json::Value) -> OutgoingHttpResponse {
    let body = serde_json::to_vec(&value).unwrap_or_default();
    let headers = serde_json::json!({"Content-Type": "application/json"});

    OutgoingHttpResponse {
        status,
        headers_json: headers.to_string(),
        body,
    }
}

// Export the component
export!(DiscourseChannel);

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_post_payload() {
        let json = r#"{
            "post": {
                "id": 123,
                "topic_id": 456,
                "username": "john_doe",
                "raw": "Hello world",
                "cooked": "<p>Hello world</p>",
                "post_number": 2,
                "reply_to_post_number": 1,
                "topic_slug": "some-topic",
                "topic_title": "Some Topic",
                "created_at": "2024-01-15T10:00:00.000Z",
                "category_id": 5
            }
        }"#;

        let payload: DiscoursePostPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.post.id, 123);
        assert_eq!(payload.post.topic_id, 456);
        assert_eq!(payload.post.username, "john_doe");
        assert_eq!(payload.post.raw, "Hello world");
        assert_eq!(payload.post.post_number, 2);
        assert_eq!(payload.post.reply_to_post_number, Some(1));
        assert_eq!(payload.post.topic_slug, Some("some-topic".to_string()));
        assert_eq!(payload.post.topic_title, Some("Some Topic".to_string()));
        assert_eq!(payload.post.category_id, Some(5));
    }

    #[test]
    fn test_parse_post_payload_minimal() {
        let json = r#"{
            "post": {
                "id": 1,
                "topic_id": 10,
                "username": "testuser",
                "raw": "Hello",
                "cooked": "<p>Hello</p>",
                "post_number": 1,
                "created_at": "2024-01-01T00:00:00Z"
            }
        }"#;

        let payload: DiscoursePostPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.post.id, 1);
        assert_eq!(payload.post.reply_to_post_number, None);
        assert_eq!(payload.post.topic_slug, None);
        assert_eq!(payload.post.category_id, None);
        assert_eq!(payload.post.post_type, None);
    }

    #[test]
    fn test_parse_post_with_whisper() {
        let json = r#"{
            "post": {
                "id": 99,
                "topic_id": 10,
                "username": "admin",
                "raw": "Secret note",
                "cooked": "<p>Secret note</p>",
                "post_number": 5,
                "created_at": "2024-01-01T00:00:00Z",
                "post_type": 4
            }
        }"#;

        let payload: DiscoursePostPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.post.post_type, Some(4));
    }

    #[test]
    fn test_metadata_roundtrip() {
        let metadata = DiscourseMessageMetadata {
            topic_id: 456,
            post_id: 123,
            post_number: 2,
            username: "john_doe".to_string(),
            topic_title: Some("Some Topic".to_string()),
            topic_slug: Some("some-topic".to_string()),
            category_id: Some(5),
            post_as: None,
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: DiscourseMessageMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.topic_id, 456);
        assert_eq!(parsed.post_id, 123);
        assert_eq!(parsed.post_number, 2);
        assert_eq!(parsed.username, "john_doe");
        assert_eq!(parsed.topic_title, Some("Some Topic".to_string()));
        assert_eq!(parsed.post_as, None);
    }

    #[test]
    fn test_metadata_with_post_as() {
        let metadata = DiscourseMessageMetadata {
            topic_id: 456,
            post_id: 123,
            post_number: 2,
            username: "john_doe".to_string(),
            topic_title: None,
            topic_slug: None,
            category_id: None,
            post_as: Some("fiscal_hawk".to_string()),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: DiscourseMessageMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.post_as, Some("fiscal_hawk".to_string()));
    }

    #[test]
    fn test_config_defaults() {
        let json = r#"{"base_url": "https://forum.example.com"}"#;
        let config: DiscourseConfig = serde_json::from_str(json).unwrap();

        assert_eq!(
            config.base_url,
            Some("https://forum.example.com".to_string())
        );
        assert_eq!(config.bot_username, None);
        assert_eq!(config.marker_token, "[ironclaw]");
        assert!(!config.handle_edited_posts);
        assert!(config.allowed_categories.is_empty());
        assert_eq!(config.owner_username, None);
    }

    #[test]
    fn test_config_full() {
        let json = r#"{
            "base_url": "https://forum.example.com",
            "bot_username": "ironclaw_bot",
            "marker_token": "[mybot]",
            "handle_edited_posts": true,
            "allowed_categories": [1, 5, 10],
            "owner_username": "admin"
        }"#;

        let config: DiscourseConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.bot_username, Some("ironclaw_bot".to_string()));
        assert_eq!(config.marker_token, "[mybot]");
        assert!(config.handle_edited_posts);
        assert_eq!(config.allowed_categories, vec![1, 5, 10]);
        assert_eq!(config.owner_username, Some("admin".to_string()));
    }

    #[test]
    fn test_marker_token_contains() {
        let marker = "[ironclaw]";
        let raw_with_marker = "Some response text\n\n---\n[ironclaw]";
        let raw_with_marker_middle = "Text [ironclaw] more text";
        let raw_without = "Just normal text without marker";

        assert!(raw_with_marker.contains(marker));
        assert!(raw_with_marker_middle.contains(marker));
        assert!(!raw_without.contains(marker));
    }

    #[test]
    fn test_extract_header_case_insensitive() {
        let headers_json = r#"{
            "Content-Type": "application/json",
            "X-Discourse-Event-Type": "post",
            "x-discourse-event": "post_created"
        }"#;

        assert_eq!(
            extract_header(headers_json, "X-Discourse-Event-Type"),
            Some("post".to_string())
        );
        assert_eq!(
            extract_header(headers_json, "x-discourse-event-type"),
            Some("post".to_string())
        );
        assert_eq!(
            extract_header(headers_json, "X-Discourse-Event"),
            Some("post_created".to_string())
        );
        assert_eq!(extract_header(headers_json, "X-Missing-Header"), None);
    }

    #[test]
    fn test_extract_header_invalid_json() {
        assert_eq!(extract_header("not json", "anything"), None);
    }

    #[test]
    fn test_thread_id_format() {
        let topic_id: i64 = 456;
        let thread_id = format!("discourse:topic:{}", topic_id);
        assert_eq!(thread_id, "discourse:topic:456");
    }

    #[test]
    fn test_truncate_multibyte_safe() {
        // 4-byte emoji at the boundary: byte-level slice would panic
        let content = "x".repeat(MAX_POST_LENGTH - 1) + "\u{1F600}";
        assert!(content.len() > MAX_POST_LENGTH);

        let mut end = MAX_POST_LENGTH;
        while !content.is_char_boundary(end) {
            end -= 1;
        }
        let truncated = &content[..end];
        assert!(truncated.len() <= MAX_POST_LENGTH);
        // Must not panic
        let _ = format!("{}\n\n*(Response truncated)*", truncated);
    }

    #[test]
    fn test_truncate_long_content() {
        let long_content = "x".repeat(MAX_POST_LENGTH + 1000);
        assert!(long_content.len() > MAX_POST_LENGTH);

        let truncated = if long_content.len() > MAX_POST_LENGTH {
            format!(
                "{}\n\n*(Response truncated)*",
                &long_content[..MAX_POST_LENGTH]
            )
        } else {
            long_content.clone()
        };

        assert!(truncated.len() < long_content.len());
        assert!(truncated.contains("*(Response truncated)*"));
    }

    #[test]
    fn test_parse_latest_posts_response() {
        let json = r#"{
            "latest_posts": [
                {
                    "id": 48,
                    "topic_id": 36,
                    "username": "ziggy",
                    "raw": "Hello world",
                    "cooked": "<p>Hello world</p>",
                    "post_number": 1,
                    "post_type": 1,
                    "created_at": "2025-12-19T10:31:52.922Z",
                    "topic_slug": "some-topic",
                    "topic_title": "Some Topic",
                    "category_id": 5
                },
                {
                    "id": 45,
                    "topic_id": 30,
                    "username": "alice",
                    "raw": "Another post",
                    "cooked": "<p>Another post</p>",
                    "post_number": 3,
                    "post_type": 1,
                    "created_at": "2025-12-18T08:00:00.000Z",
                    "reply_to_post_number": 2
                }
            ]
        }"#;

        let response: DiscourseLatestPostsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.latest_posts.len(), 2);
        assert_eq!(response.latest_posts[0].id, 48);
        assert_eq!(response.latest_posts[0].username, "ziggy");
        assert_eq!(response.latest_posts[0].topic_id, 36);
        assert_eq!(response.latest_posts[0].category_id, Some(5));
        assert_eq!(response.latest_posts[1].id, 45);
        assert_eq!(response.latest_posts[1].reply_to_post_number, Some(2));
        assert_eq!(response.latest_posts[1].topic_slug, None);
    }

    #[test]
    fn test_parse_create_post_response_success() {
        let json = r#"{"id": 789, "post_number": 3}"#;
        let response: DiscourseCreatePostResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.id, Some(789));
        assert_eq!(response.post_number, Some(3));
        assert!(response.errors.is_none());
    }

    #[test]
    fn test_parse_create_post_response_error() {
        let json = r#"{"errors": ["Title is too short"], "error_type": "invalid_parameters"}"#;
        let response: DiscourseCreatePostResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.id, None);
        assert_eq!(
            response.errors,
            Some(vec!["Title is too short".to_string()])
        );
    }

    fn make_post(id: i64, topic_id: i64, username: &str, raw: &str) -> DiscoursePost {
        DiscoursePost {
            id,
            topic_id,
            username: username.to_string(),
            raw: raw.to_string(),
            cooked: String::new(),
            post_number: 1,
            reply_to_post_number: None,
            topic_slug: None,
            topic_title: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            category_id: None,
            post_type: None,
        }
    }

    #[test]
    fn test_poll_filtering_and_ordering() {
        // /posts.json returns newest-first; on_poll filters id > last and sorts ascending
        let posts = [
            make_post(105, 10, "alice", "Post 105"),
            make_post(103, 10, "bob", "Post 103"),
            make_post(100, 9, "charlie", "Post 100"),
        ];

        let last_post_id: i64 = 102;

        let mut new_posts: Vec<&DiscoursePost> =
            posts.iter().filter(|p| p.id > last_post_id).collect();
        new_posts.sort_by_key(|p| p.id);

        assert_eq!(new_posts.len(), 2);
        assert_eq!(new_posts[0].id, 103); // oldest first
        assert_eq!(new_posts[1].id, 105);

        let max_id = new_posts.iter().map(|p| p.id).max().unwrap();
        assert_eq!(max_id, 105);
    }

    #[test]
    fn test_first_poll_bootstrap_seeds_max_id() {
        let posts = [
            make_post(500, 10, "alice", "Latest"),
            make_post(498, 9, "bob", "Older"),
        ];

        let last_post_id: i64 = 0;

        // Bootstrap: seed max ID without emitting
        let max_id = posts.iter().map(|p| p.id).max();
        assert_eq!(max_id, Some(500));

        // Without bootstrap, all posts pass the filter (the bug we're preventing)
        let would_emit: Vec<&DiscoursePost> =
            posts.iter().filter(|p| p.id > last_post_id).collect();
        assert_eq!(would_emit.len(), 2);
    }

    #[test]
    fn test_first_poll_bootstrap_empty_forum() {
        let posts: Vec<DiscoursePost> = vec![];
        let max_id = posts.iter().map(|p| p.id).max();
        assert_eq!(max_id, None); // No seed, next poll retries
    }
}
