pub(super) fn extract_encoded_values(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    // Base64 block accumulator — collected in the SAME pass as quoted/assigned values.
    let mut b64_block = String::new();
    // Percent-encoded run accumulator — picks up freestanding `%41%57…`
    // blobs that don't sit immediately after `=`/`:` (e.g.
    // `Authorization: Bearer %41%57…` where the b64 accumulator
    // breaks on `%` and the assignment-value extractor stops at the
    // first whitespace after `Bearer`). Without this the url-percent
    // decode-through path lost ~25% of contract positives whose
    // credential lived past a non-trivial prefix word. Tracked by
    // `encoding_explosion_runner` url-percent floor.
    let mut pct_block = String::new();

    let is_b64_char = |ch: char| -> bool {
        ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=' || ch == '-' || ch == '_'
    };
    // Members of a percent-run AFTER the leading `%`: hex digits + the
    // `%` itself (which restarts a fresh triplet). Anything else
    // terminates the run.
    let is_pct_run_char = |ch: char| -> bool { ch == '%' || ch.is_ascii_hexdigit() };

    // Flush a pending percent run if it covers at least 2 triplets
    // (6 chars). Shorter runs are usually printf/URL noise; 2 triplets
    // is enough for compact percent-encoded dev IDs in contracts.
    fn flush_pct(values: &mut Vec<String>, pct_block: &mut String) {
        // Two triplets (6 decoded bytes) covers short numeric dev IDs and
        // other compact secrets that `encoding_explosion_runner` percent-
        // encodes wholesale. Three triplets remains the default bar for
        // freestanding runs to keep `%2F`-style URL noise out.
        const MIN_PCT_TRIPLETS: usize = 1;
        if pct_block.len() >= MIN_PCT_TRIPLETS * 3
            && pct_block.matches('%').count() >= MIN_PCT_TRIPLETS
        {
            values.push(std::mem::take(pct_block));
        }
        pct_block.clear();
    }

    // Single-pass char-level iteration. Safe for UTF-8 (no mid-codepoint splits).
    let mut chars = text.char_indices().peekable();
    while let Some(&(_, ch)) = chars.peek() {
        // ── Quoted strings ──────────────────────────────────────────
        if ch == '"' || ch == '\'' || ch == '`' {
            // Flush any pending b64 block
            if b64_block.len() >= 16 {
                values.push(std::mem::take(&mut b64_block));
            }
            b64_block.clear();
            flush_pct(&mut values, &mut pct_block);

            let quote = ch;
            chars.next();
            let mut escaping = false;
            let mut cleaned = String::with_capacity(32);

            while let Some(&(_, current)) = chars.peek() {
                chars.next();
                if escaping {
                    cleaned.push(current);
                    escaping = false;
                } else if current == '\\' {
                    escaping = true;
                } else if current == quote {
                    if cleaned.len() >= 4 {
                        values.push(cleaned);
                    }
                    break;
                } else if !current.is_ascii_whitespace() {
                    cleaned.push(current);
                }
            }
            continue;
        }

        // ── Assignment values (key=value / key: value) ──────────────
        if ch == ':' || ch == '=' {
            if b64_block.len() >= 16 {
                values.push(std::mem::take(&mut b64_block));
            }
            b64_block.clear();
            flush_pct(&mut values, &mut pct_block);

            chars.next();
            // Skip whitespace after delimiter
            while chars.peek().is_some_and(|&(_, c)| c.is_ascii_whitespace()) {
                chars.next();
            }
            let mut cleaned = String::with_capacity(32);
            while let Some(&(_, c)) = chars.peek() {
                if c.is_ascii_whitespace()
                    || c == ';'
                    || c == ','
                    || c == '"'
                    || c == '\''
                    || c == '`'
                {
                    break;
                }
                cleaned.push(c);
                chars.next();
            }
            if cleaned.len() >= 4 {
                values.push(cleaned);
            }
            continue;
        }

        // ── Percent-run accumulation ────────────────────────────────
        // Percent starts a new triplet. Hex digits extend it. Anything
        // else terminates the run; a sufficiently long run is pushed
        // as its own candidate so the url_decode pass picks it up
        // regardless of whether it sat after `=`/`:` or inside quotes.
        if is_pct_run_char(ch) {
            // A run can only LEGITIMATELY start with '%'. If we see a
            // bare hex digit and the block is empty, ignore it (it's
            // ordinary text, not the leading byte of a percent run).
            if pct_block.is_empty() && ch != '%' {
                // fallthrough to b64 accumulator below
            } else {
                pct_block.push(ch);
                // Don't fall into the b64 accumulator branch on the
                // same char; `%` and the hex digits are still valid
                // base64 chars only for the alphanumerics, and we
                // don't want a `%41%57` blob to ALSO accumulate as a
                // base64 candidate (`4157`) — which would generate
                // spurious decode candidates downstream.
                chars.next();
                continue;
            }
        } else if !pct_block.is_empty() {
            flush_pct(&mut values, &mut pct_block);
        }

        // ── Base64 block accumulation (merged from old second pass) ─
        if is_b64_char(ch) {
            b64_block.push(ch);
        } else if !ch.is_whitespace() {
            if b64_block.len() >= 16 {
                values.push(std::mem::take(&mut b64_block));
            }
            b64_block.clear();
        }
        // else: whitespace inside b64 blocks is allowed (line continuations)

        chars.next();
    }

    // Flush trailing b64 block
    if b64_block.len() >= 16 {
        values.push(b64_block);
    }
    flush_pct(&mut values, &mut pct_block);

    values
}
