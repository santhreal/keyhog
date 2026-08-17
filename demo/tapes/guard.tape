# Perpetual Guard recording: registering a repository, baseline indexing,
# status inspection, and sub-millisecond clean staged commit scan.
Output demo/keyhog-guard.gif
Output demo/keyhog-guard.mp4

Require keyhog

Set Shell "bash"
Set Width 1380
Set Height 820
Set Padding 26
Set FontSize 13
Set Theme "Dracula"
Set Framerate 30
Set TypingSpeed 28ms

Hide
Type "clear" Enter
Sleep 250ms
Show

Type "# Start perpetual daemon with auto-routed GPU / SIMD acceleration"
Enter
Type "keyhog daemon start --backend auto"
Sleep 400ms
Enter

# Daemon initialization
Sleep 2500ms

Type "# Register repository for continuous guard protection and indexing"
Enter
Type "keyhog guard add . --mode repo"
Sleep 400ms
Enter

# Indexing & reconciliation
Sleep 3000ms

Type "# Inspect guard status and memory-backed index attestation metrics"
Enter
Type "keyhog guard status ."
Sleep 400ms
Enter

# Status output
Sleep 2000ms

Type "# Run instant clean staged commit scan (cached attestation hit)"
Enter
Type "keyhog scan --git-staged"
Sleep 400ms
Enter

# Instant scan output
Sleep 3000ms

# Hold on final state
Sleep 2000ms

Hide
Type "keyhog daemon stop" Enter
Sleep 500ms
