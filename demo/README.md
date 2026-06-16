# demo

Synthetic application tree used to drive the `keyhog scan` demo
recording in `demo.tape`. Every "credential" in this directory is
either:

1. A documented example value from the provider's own docs (Stripe's
   `sk_live_4eC39H...`, Slack's `xoxb-123456789...`).
2. A randomly generated string shaped like the real format but with
   no live counterpart anywhere.

**Nothing here grants access to any real service.** The file
contents exist to exercise keyhog's detector regexes during demos,
recordings, and local smoke tests. Do NOT use these as starter
values for actual deployments. Do NOT replicate the file names in
your real project (the `app/.env.production` shape is intentional
demo bait for screenshots).

Run `keyhog scan demo` from the keyhog repo root to scan this
directory — the text output the demo GIF (`demo.tape`) is based on.
