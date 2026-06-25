# Resolved-config recording: `keyhog config --effective` prints the exact scan
# configuration (compiled defaults <- tool.toml <- CLI overrides) that would
# reach the scanner for this invocation, WITHOUT scanning. The visual for the
# README "Configuration is two-tier and provable" section: every knob is
# inspectable, and an override on the command line is shown resolving through.
Output demo/keyhog-config.gif

Require keyhog

Set Shell "bash"
Set Width 1240
Set Height 900
Set Padding 26
Set FontSize 13
Set Theme "Dracula"
Set Framerate 30
Set TypingSpeed 26ms

Hide
Type "clear" Enter
Sleep 250ms
Show

# Resolve the config for a scan, overriding one knob on the CLI to show the
# precedence chain land in the printed result (min_confidence 0.4 -> 0.6).
Type "keyhog config --effective demo --min-confidence 0.6 | head -n 26"
Sleep 500ms
Enter

# Resolved [effective-config] block renders.
Sleep 2200ms
# Hold on the populated knob list.
Sleep 2000ms

Hide
Sleep 200ms
