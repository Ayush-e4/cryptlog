Output assets/demo.gif

Set FontSize 18
Set Width 950
Set Height 420
Set Padding 30
Set Theme "Catppuccin Macchiato"
Set WindowBar Colorful
Set BorderRadius 10

Hide
Type "export PATH=/Users/ayush/Desktop/cryptlog/target/release:$PATH"
Enter
Type "export CRYPTLOG_PATH=audit.clog"
Enter
Type "rm -f audit.clog"
Enter
Type "clear"
Enter
Show

Type "cryptlog append 'user:42 logged in from 192.168.1.1'"
Sleep 300ms
Enter 
Sleep 1s

Type "cryptlog append 'user:42 deleted invoice:991'"
Sleep 300ms
Enter
Sleep 1s

Type "cryptlog append 'admin:01 exported all records'"
Sleep 300ms
Enter
Sleep 1s

Type "cryptlog tail"
Sleep 300ms
Enter
Sleep 3s

Type "# We'll use dd to flip a byte and simulate tampering"
Sleep 500ms
Enter
Sleep 500ms

Type "printf '\x00' | dd of=audit.clog bs=1 seek=120 count=1 conv=notrunc 2>/dev/null"
Sleep 300ms
Enter
Sleep 1s

Type "cryptlog verify"
Sleep 500ms
Enter
Sleep 4s
