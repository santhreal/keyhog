Output demo/keyhog-demo.gif
Output demo/keyhog-demo.mp4
Output demo/keyhog-scan.gif
Output demo/keyhog-scan.mp4

Require keyhog

Set Shell "bash"
Set Width 1280
Set Height 820
Set Padding 24
Set FontSize 14
Set Theme "Dracula"
Set Framerate 30
Set TypingSpeed 32ms

Hide
Type "export CLICOLOR_FORCE=1" Enter
Type "clear" Enter
Sleep 200ms
Show

Type "keyhog scan demo/app demo/config"
Sleep 400ms
Enter

# Output findings stream in full color
Sleep 4000ms

Type "keyhog explain stripe-secret-key"
Sleep 400ms
Enter

# Output detector spec & remediation guide
Sleep 4000ms

Sleep 1500ms
