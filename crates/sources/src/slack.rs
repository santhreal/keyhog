//! Slack source: fetches messages from Slack channels using the Web API.
//!
//! This allows KeyHog to identify secrets leaked in chat history.
//! Requires a Slack API token (Bot or User) with `channels:history` and `groups:history` scopes.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use reqwest::blocking::Client;
use serde::Deserialize;

/// Scan Slack messages via the `conversations.history` API.
pub struct SlackSource {
    token: String,
    lookback_messages: usize,
}

impl SlackSource {
    /// Create a new Slack source.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            lookback_messages: 1000,
        }
    }

    /// Set how many messages to fetch per channel.
    pub fn with_lookback(mut self, n: usize) -> Self {
        self.lookback_messages = n;
        self
    }
}

impl Source for SlackSource {
    fn name(&self) -> &str {
        "slack"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match self.collect_chunks() {
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
    data: T.into(),
}

#[derive(Deserialize)]
struct ConversationsList {
    channels: Vec<Channel>,
}

#[derive(Deserialize)]
struct Channel {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct History {
    messages: Vec<Message>,
}

#[derive(Deserialize)]
struct Message {
    user: Option<String>,
    text: String,
    ts: String,
}

impl SlackSource {
    fn collect_chunks(&self) -> Result<Vec<Chunk>, SourceError> {
        let client = Client::builder()
            .timeout(crate::timeouts::HTTP_REQUEST)
            .build()
            .map_err(|e| SourceError::Other(format!("failed to build Slack client: {e}")))?;

        let channels = self.list_channels(&client)?;

        // Concurrent per-channel history fetch. Slack's tier-2 rate limit is
        // 20+ requests/minute; cap parallelism at 8 to leave headroom for the
        // burst budget. Was sequential — see audits/legendary-2026-04-26.
        use rayon::prelude::*;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .map_err(|e| SourceError::Other(format!("rayon pool build: {e}")))?;
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
        let resp: SlackResponse<ConversationsList> = client
            .get("https://slack.com/api/conversations.list")
            .bearer_auth(&self.token)
            .query(&[("types", "public_channel,private_channel")])
            .send()
            .map_err(|e| SourceError::Other(e.to_string()))?
            .json()
            .map_err(|e| SourceError::Other(e.to_string()))?;

        if !resp.ok {
            return Err(SourceError::Other(format!(
                "Slack API error: {}",
                resp.error.unwrap_or_default()
            )));
        }
        Ok(resp.data.channels)
    }

    fn fetch_history(
        &self,
        client: &Client,
        channel_id: &str,
    ) -> Result<Vec<Message>, SourceError> {
        let resp: SlackResponse<History> = client
            .get("https://slack.com/api/conversations.history")
            .bearer_auth(&self.token)
            .query(&[
                ("channel", channel_id),
                ("limit", &self.lookback_messages.to_string()),
            ])
            .send()
            .map_err(|e| SourceError::Other(e.to_string()))?
            .json()
            .map_err(|e| SourceError::Other(e.to_string()))?;

        if !resp.ok {
            return Err(SourceError::Other(format!(
                "Slack API error: {}",
                resp.error.unwrap_or_default()
            )));
        }
        Ok(resp.data.messages)
    }
}
