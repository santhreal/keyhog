# Hero scan recording: `keyhog scan` over the synthetic demo/ tree, run on the
# GPU region-presence backend (RTX 5090) — the premium fast path.
# Renders the real headless scan surface — boxed findings with severity,
# confidence, file:line, and remediation, then the results summary and the
# coverage-gap (skipped-file) notice that keeps "N findings" honest.
Output demo/keyhog-scan.gif

Require keyhog

Set Shell "bash"
Set Width 1240
Set Height 820
Set Padding 26
Set FontSize 13
Set Theme "Dracula"
Set Framerate 30
Set TypingSpeed 26ms

Hide
Type "clear" Enter
Sleep 250ms
Show

Type "keyhog scan demo --backend gpu-region-presence"
Sleep 500ms
Enter

# Detector compile + scan; findings stream out, then the summary lands.
Sleep 6s
# Hold on the populated end-state (summary + coverage-gap line).
Sleep 1500ms

Hide
Sleep 200ms
