Output keyhog-demo.gif

Set Width 1380
Set Height 800
Set Padding 28
Set FontSize 14
Set Theme "Dracula"
Set Framerate 30
Set TypingSpeed 28ms

# Records a real `keyhog scan` of the synthetic demo/ tree: the headless
# scan surface every user actually runs. Hide covers the cold-start
# (detector compile + GPU init) so the visible portion of the gif is all
# live output - findings printed with file:line, severity, and the
# end-of-run summary counters.
Hide
Type "clear" Enter
Sleep 100ms
Type "keyhog scan demo" Enter

# Cold-start window: detector compile + GPU init happen off-screen so the
# visible frames below capture the findings + summary, not boot dead-air.
Sleep 4500ms
Show

# Visible: findings stream out, then the summary line lands.
Sleep 6s

# Hold on the populated end-state.
Sleep 800ms

Hide
Sleep 200ms
