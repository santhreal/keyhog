# Honest health-check recording: `keyhog doctor`: host probe (CPU/SIMD/GPU,
# Hyperscan), install + PATH resolution, embedded detector count, and the
# four-way self-test: scan engine end-to-end, GPU scan path (AC kernel), GPU
# literal set, and the GPU MoE shader proven against the CPU reference. This is
# the visual for the README "Honest self-test" section: keyhog never reports
# green unless the GPU path actually proves itself on this host.
Output demo/keyhog-doctor.gif

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

Type "keyhog doctor"
Sleep 500ms
Enter

# Host probe + install resolution + self-test sweep render.
Sleep 3500ms
# Hold on the populated self-test (each line lands PASS).
Sleep 2500ms

Hide
Sleep 200ms
