# Output-formats recording: keyhog speaks every CI/SIEM dialect from one scan.
# Shows the machine-readable stdout payloads, json (pipelines), sarif (code
# scanning), csv (spreadsheets/BI), over the same demo/ tree. Diagnostic
# stderr (banner, progress, Law-10 notices) is piped away with 2>/dev/null so
# the frame holds the clean structured payload a downstream tool consumes.
Output demo/keyhog-formats.gif

Require keyhog

Set Shell "bash"
Set Width 1240
Set Height 760
Set Padding 26
Set FontSize 13
Set Theme "Dracula"
Set Framerate 30
Set TypingSpeed 24ms

Hide
Type "clear" Enter
Sleep 200ms
Show

Type "# one scan, nine formats: text · json · jsonl · sarif · csv · html · junit · github · gitlab"
Sleep 600ms
Enter
Sleep 400ms

Type "keyhog scan demo --backend gpu-region-presence --format json 2>/dev/null | head -c 240; echo"
Sleep 500ms
Enter
Sleep 2600ms

Type "keyhog scan demo --backend gpu-region-presence --format sarif 2>/dev/null | head -c 240; echo"
Sleep 500ms
Enter
Sleep 2600ms

Type "keyhog scan demo --backend gpu-region-presence --format csv 2>/dev/null | head -n 4"
Sleep 500ms
Enter
Sleep 2600ms

Hide
Sleep 200ms
