# Terminal demo for the README. Regenerate with:  make demo
# Records the real CLI against examples/; nothing is staged.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1360
Set Height 560
Set Padding 18
Set Theme "GitHub Dark"
Set TypingSpeed 28ms

Hide
Type "export PATH=/vhs:$PATH PS1='$ ' && cd /vhs && clear"
Enter
Show

Type "admission-replay compare examples/audit.log examples/policies/*.yaml --bad examples/bad.txt"
Enter
Sleep 8s

Type "clear"
Enter
Sleep 300ms

Type "admission-replay replay examples/audit.log examples/policies/strict-baseline.yaml --bad examples/bad.txt --show missed"
Enter
Sleep 7s

Type "clear"
Enter
Sleep 300ms

Type "admission-replay replay examples/audit.log examples/policies/targeted.yaml --bad examples/bad.txt \"
Enter
Type "    --show caught --fail-on-block --fail-on-miss; echo exit status $?"
Enter
Sleep 9s
