//! Slack source: fetches messages from Slack channels using the Web API.
//!
//! This allows KeyHog to identify secrets leaked in chat history.
//! Requires a Slack API token (Bot or User) with `channels:history` and `groups:history` scopes.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use reqwest::blocking::{Client, Response};
use serde::{de::DeserializeOwned, Deserialize};

/// Scan Slack messages via the `conversations.history` API.
pub struct SlackSource {
    token: String,
    lookback_messages: usize,
    /// Shared HTTP policy (proxy, insecure_tls, ua_suffix, timeout). Defaults to
    /// the explicit-only `HttpClientConfig` policy; no environment variable can
    /// reroute Slack API calls. Set via `with_http_config` so the CLI's
    /// `--proxy` / `--insecure` reach this source instead of bypassing the
    /// configured corporate proxy or the operator's Burp interception.
    http: crate::http::HttpClientConfig,
}

impl SlackSource {
    /// Create a new Slack source.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            lookback_messages: 1000,
            http: crate::http::HttpClientConfig {
                ua_suffix: Some("slack".into()),
                ..Default::default()
            },
        }
    }

    /// Override the shared HTTP policy. Threads CLI `--proxy` / `--insecure`
    /// into the Slack API client.
    pub(crate) fn with_http_config(mut self, http: crate::http::HttpClientConfig) -> Self {
        self.http = http;
        self
    }
}

impl Source for SlackSource {
    fn name(&self) -> &str {
        "slack"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        // `reqwest::blocking` must run off the CLI's `#[tokio::main]` thread
        // (dropping its internal runtime in an async context aborts the
        // process). Collection is eager, so run it on a scoped std thread with
        // no ambient tokio runtime.
        let result = std::thread::scope(|s| match s.spawn(|| self.collect_chunks()).join() {
            Ok(result) => result,
            Err(_panic) => Err(SourceError::Other(
                "slack fetch thread panicked".to_string(),
            )),
        });
        match result {
            Ok(chunks) => Box::new(chunks.into_iter().map(Ok)),
            Err(e) => Box::new(std::iter::once(Err(e))),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Deserialize)]
struct SlackResponse<T> {
    ok: bool,
    error: Option<String>,
    #[serde(flatten)]
    data: T,
}

#[derive(Deserialize)]
struct ConversationsList {
    channels: Option<Vec<Channel>>,
}

#[derive(Deserialize)]
struct Channel {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct History {
    messages: Option<Vec<Message>>,
}

#[derive(Deserialize)]
struct Message {
    user: Option<String>,
    text: String,
    ts: String,
}

const CONVERSATIONS_LIST: &str = "conversations.list";
const CONVERSATIONS_HISTORY: &str = "conversations.history";

fn slack_error_code(error: Option<&str>) -> &str {
    match error {
        Some(code) if !code.trim().is_empty() => code.trim(),
        _ => "<no error field>",
    }
}

fn parse_slack_response<T>(endpoint: &str, body: &str) -> Result<SlackResponse<T>, SourceError>
where
    T: DeserializeOwned,
{
    serde_json::from_str(body).map_err(|error| {
        SourceError::Other(format!(
            "failed to parse Slack {endpoint} response: {error}"
        ))
    })
}

fn read_slack_response<T>(
    endpoint: &str,
    response: Response,
) -> Result<SlackResponse<T>, SourceError>
where
    T: DeserializeOwned,
{
    let status = response.status();
    let body = response.text().map_err(|error| {
        SourceError::Other(format!(
            "failed to read Slack {endpoint} response body: {error}"
        ))
    })?;
    match parse_slack_response(endpoint, &body) {
        Ok(resp) => {
            if !status.is_success() && resp.ok {
                return Err(SourceError::Other(format!(
                    "Slack API {endpoint} returned HTTP {status} with ok=true"
                )));
            }
            Ok(resp)
        }
        Err(error) if !status.is_success() => Err(SourceError::Other(format!(
            "Slack API {endpoint} returned HTTP {status} and an unreadable JSON body: {error}"
        ))),
        Err(error) => Err(error),
    }
}

fn channels_from_response(
    resp: SlackResponse<ConversationsList>,
) -> Result<Vec<Channel>, SourceError> {
    if !resp.ok {
        return Err(SourceError::Other(format!(
            "Slack API {CONVERSATIONS_LIST} error: {}",
            slack_error_code(resp.error.as_deref())
        )));
    }
    match resp.data.channels {
        Some(channels) => Ok(channels),
        None => Err(SourceError::Other(format!(
            "Slack API {CONVERSATIONS_LIST} ok response missing channels"
        ))),
    }
}

fn messages_from_response(
    resp: SlackResponse<History>,
    channel_id: &str,
) -> Result<Vec<Message>, SourceError> {
    if !resp.ok {
        return Err(SourceError::Other(format!(
            "Slack API {CONVERSATIONS_HISTORY} error for channel {channel_id}: {}",
            slack_error_code(resp.error.as_deref())
        )));
    }
    match resp.data.messages {
        Some(messages) => Ok(messages),
        None => Err(SourceError::Other(format!(
            "Slack API {CONVERSATIONS_HISTORY} ok response for channel {channel_id} missing messages"
        ))),
    }
}

pub(crate) fn conversations_list_len_for_test(body: &str) -> Result<usize, SourceError> {
    let resp = parse_slack_response::<ConversationsList>(CONVERSATIONS_LIST, body)?;
    channels_from_response(resp).map(|channels| channels.len())
}

pub(crate) fn history_len_for_test(body: &str, channel_id: &str) -> Result<usize, SourceError> {
    let resp = parse_slack_response::<History>(CONVERSATIONS_HISTORY, body)?;
    messages_from_response(resp, channel_id).map(|messages| messages.len())
}

impl SlackSource {
    fn collect_chunks(&self) -> Result<Vec<Chunk>, SourceError> {
        let http = if self.http.timeout.is_none() {
            let mut h = self.http.clone();
            h.timeout = Some(crate::timeouts::HTTP_REQUEST);
            h
        } else {
            self.http.clone()
        };
        let client = crate::http::blocking_client_builder(&http)
            .map_err(SourceError::Other)?
            .build()
            .map_err(|e| SourceError::Other(format!("failed to build Slack client: {e}")))?;

        let channels = self.list_channels(&client)?;

        // Concurrent per-channel history fetch. Slack's tier-2 rate limit is
        // 20+ requests/minute; cap parallelism at 8 to leave headroom for the
        // burst budget. Was sequential - see docs/EXECUTION_PLAN.md.
        use rayon::prelude::*;
        let pool = crate::parallel_fetch::bounded_fetch_pool(
            "slack",
            crate::parallel_fetch::REMOTE_API_FETCH_THREADS,
        )?;
        let per_channel: Vec<Result<Vec<Chunk>, SourceError>> = pool.install(|| {
            channels
                .par_iter()
                .map(|channel| -> Result<Vec<Chunk>, SourceError> {
                    let messages = self.fetch_history(&client, &channel.id)?;
                    let mut channel_chunks = Vec::new();
                    let mut channel_buffer = String::new();
                    for msg in messages {
                        if let Some(user) = &msg.user {
                            channel_buffer
                                .push_str(&format!("\n[USER: {} TS: {}]\n", user, msg.ts));
                        }
                        channel_buffer.push_str(&msg.text);
                        channel_buffer.push('\n');
                        if channel_buffer.len() > 64 * 1024 {
                            channel_chunks.push(Chunk {
                                data: std::mem::take(&mut channel_buffer).into(),
                                metadata: ChunkMetadata {
                                    base_offset: 0,
                                    base_line: 0,
                                    source_type: "slack".into(),
                                    path: Some(format!("slack://#{}", channel.name)),
                                    ..Default::default()
                                },
                            });
                        }
                    }
                    if !channel_buffer.is_empty() {
                        channel_chunks.push(Chunk {
                            data: channel_buffer.into(),
                            metadata: ChunkMetadata {
                                base_offset: 0,
                                base_line: 0,
                                source_type: "slack".into(),
                                path: Some(format!("slack://#{}", channel.name)),
                                ..Default::default()
                            },
                        });
                    }
                    Ok(channel_chunks)
                })
                .collect()
        });

        let mut chunks = Vec::new();
        for result in per_channel {
            chunks.extend(result?);
        }
        Ok(chunks)
    }

    fn list_channels(&self, client: &Client) -> Result<Vec<Channel>, SourceError> {
        let resp = client
            .get("https://slack.com/api/conversations.list")
            .bearer_auth(&self.token)
            .query(&[("types", "public_channel,private_channel")])
            .send()
            .map_err(|error| {
                SourceError::Other(format!(
                    "Slack API {CONVERSATIONS_LIST} request failed: {error}"
                ))
            })?;
        let resp = read_slack_response(CONVERSATIONS_LIST, resp)?;
        channels_from_response(resp)
    }

    fn fetch_history(
        &self,
        client: &Client,
        channel_id: &str,
    ) -> Result<Vec<Message>, SourceError> {
        let resp = client
            .get("https://slack.com/api/conversations.history")
            .bearer_auth(&self.token)
            .query(&[
                ("channel", channel_id),
                ("limit", &self.lookback_messages.to_string()),
            ])
            .send()
            .map_err(|error| {
                SourceError::Other(format!(
                    "Slack API {CONVERSATIONS_HISTORY} request failed for channel {channel_id}: {error}"
                ))
            })?;
        let resp = read_slack_response(CONVERSATIONS_HISTORY, resp)?;
        messages_from_response(resp, channel_id)
    }
}
