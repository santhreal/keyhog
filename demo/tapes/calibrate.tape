# Onboarding recording: the visible autoroute calibration phase of the install.
# `install.sh --calibrate` measures every real workload class on THIS host 
# stdin, small/large files, many-file trees, decode-heavy, git history/blobs/diff,
# a loopback web URL, and a live `docker build` image, timing each backend and
# persisting only a route it can prove fastest (or the sound lowest-overhead
# tie-break). This is the visual for the README "calibration" section: keyhog's
# auto route is measured on your hardware, never guessed, and the install refuses
# to finish unless every workload class calibrates.
Output demo/keyhog-calibrate.gif

Require keyhog

Set Shell "bash"
Set Width 1240
Set Height 940
Set Padding 26
Set FontSize 13
Set Theme "Dracula"
Set Framerate 24
Set TypingSpeed 26ms

Hide
Type "clear" Enter
Sleep 250ms
Show

Type "sh install.sh --calibrate --no-prompt"
Sleep 500ms
Enter

# The 16-probe sweep streams: each workload class spins, measures every backend,
# and lands PASS. Held for the full sweep (~36s on this host).
Sleep 40s
# Hold on the decisions summary + "calibration phase complete" payoff.
Sleep 2500ms

Hide
Sleep 200ms
