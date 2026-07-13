# Autoroute backend recording: `keyhog backend`: the hardware probe plus the
# size-driven routing decision matrix. Small inputs route to simd-regex
# (GPU byte thresholds not met); once a chunk crosses the per-tier min_bytes
# the router switches to gpu-region-presence. This is the visual for the
# README "Autoroute Contract" section: the selection is a measured, explainable
# function of host + input size, not a guess.
Output demo/keyhog-backend.gif

Require keyhog

Set Shell "bash"
Set Width 1500
Set Height 1000
Set Padding 26
Set FontSize 13
Set Theme "Dracula"
Set Framerate 30
Set TypingSpeed 26ms

Hide
Type "clear" Enter
Sleep 250ms
Show

Type "keyhog backend"
Sleep 500ms
Enter

# Hardware probe + routing decision matrix render.
Sleep 2s
# Hold on the populated matrix so the simd-regex -> gpu-region-presence
# crossover is readable.
Sleep 3s

Hide
Sleep 200ms
