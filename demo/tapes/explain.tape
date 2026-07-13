# Detector anatomy recording: `keyhog explain <id>`: the full spec dump for one
# detector (patterns, keywords, verification endpoint) plus the service-keyed
# rotation + remediation guide. Visual for the README "What it catches" section:
# every finding is explainable down to the regex and comes with a fix.
#
# The `cd` to a neutral dir runs under Hide so the recording shows only the
# clean explain output. (Run from a directory that holds a live `detectors/`
# TOML corpus and explain additionally re-validates that corpus out loud, that
# is the live-corpus audit path, not the embedded-default a normal user hits.)
Output demo/keyhog-explain.gif

Require keyhog

Set Shell "bash"
Set Width 1240
Set Height 820
Set Padding 26
Set FontSize 14
Set Theme "Dracula"
Set Framerate 30
Set TypingSpeed 28ms

Hide
Type "cd /tmp" Enter
Type "clear" Enter
Sleep 250ms
Show

Type "keyhog explain github-classic-pat"
Sleep 500ms
Enter

# Spec dump + rotation/remediation guide render.
Sleep 1500ms
# Hold on the populated explanation.
Sleep 2800ms

Hide
Sleep 200ms
