Output keyhog-demo.gif

Set Width 1380
Set Height 800
Set Padding 28
Set FontSize 14
Set Theme "Dracula"
Set Framerate 30
Set TypingSpeed 28ms

# Hide the dead-air cold-start: ~10s of keyhog tui boot (detector
# compile + GPU init + first chunk scan) happen while vhs is in
# Hide mode. We come out of Hide just before the first finding
# lands so the visible portion of the gif is all live action -
# findings streaming in, stats counters ticking up, banner flipping
# from yellow "scanning" to green "scan complete".
Hide
Type "clear" Enter
Sleep 100ms
Type "keyhog tui demo --throttle-ms 600 --feed-depth 18" Enter

# Cold-start window. 6.5s captures the compile + GPU init phase
# but leaves the actual file scan to happen on-screen. The 600ms
# throttle means 11 demo files take ~6.6s to walk - perfectly
# paced for the visible-frame window below.
Sleep 6500ms
Show

# Visible: findings stream in, counters update, banner flips green
Sleep 8s

# Hold on the populated end-state
Sleep 600ms

# Clean exit
Hide
Type "q"
Sleep 400ms
