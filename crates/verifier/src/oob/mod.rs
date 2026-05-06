//! Out-of-band (OOB) callback verification via an embedded interactsh client.
//!
//! ## Why this exists
//!
//! The classical verifier asks: "does the API return 200?" — a clever per-
//! service heuristic answer that tells us the credential parses. For
//! webhook- and callback-shaped credentials (Slack incoming webhooks, Discord
//! webhooks, generic alerting endpoints, mailers) "200 OK" is necessary but
//! not sufficient: a dead webhook URL can still 200 the probe, and a service
//! that 200s every payload tells us nothing about exfil capability.
//!
//! OOB verification closes the gap. We mint a unique per-finding subdomain
//! pointed at an interactsh collector, embed it in the verification probe,
//! send the probe, and wait for the service to call back. If the callback
//! arrives, the credential is **provably exfil-capable** — the service
//! actually fetched our collector with attacker-controlled traffic.
//!
//! ## Trust model
//!
//! - The OOB client is opt-in (`--verify-oob`). Default scans never make
//!   a single OOB request.
//! - Public collectors (oast.fun, oast.pro, …) see only the correlation IDs
//!   we mint and the IPs of the services calling back — never the credential
//!   itself. The credential is sent **to the legitimate service**, not to
//!   the collector.
//! - Self-host (`projectdiscovery/interactsh-server`) for sensitive scans.
//!   Set `--oob-server <host>` and the client speaks to your collector.
//!
//! ## Protocol
//!
//! Implements the `projectdiscovery/interactsh` register/poll protocol:
//!
//! 1. Generate a fresh RSA-2048 keypair on engine startup.
//! 2. POST `/register` with `{public-key: PEM, secret-key: UUID, correlation-id: 20 lowercase a-z0-9}`.
//! 3. Each per-finding URL is `{correlation-id}{13 random}.{server}` (33 chars total).
//! 4. Background loop polls `/poll?id={cid}&secret={uuid}`.
//! 5. Each interaction comes back as `{aes_key: RSA-OAEP(sha256) wrapping a 32-byte key, data: [base64(IV[16] || AES-256-CFB(payload))]}`.
//! 6. Decrypt → JSON `{protocol, unique-id, raw-request, remote-address, timestamp}`.
//! 7. Match `unique-id` (full 33-char subdomain prefix) to the finding that minted it.
//! 8. POST `/deregister` on shutdown.

mod client;
mod session;

pub use client::{Interaction, InteractionProtocol, InteractshClient, InteractshError};
pub use session::{OobConfig, OobObservation, OobSession};
