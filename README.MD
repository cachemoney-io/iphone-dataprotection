# iOS forensics tools

## Alphanumeric passcode fork

This fork adds support for alphanumeric passcodes (keyboard type 2) and wordlist attacks.
It still supports numeric passcodes, and can (almost) be used as a drop-in replacement for the original tool.
However, I removed support for automatic progress saving/loading, though you can manually start from a given passcode using the `-r` option.

### Usage

```
./bruteforce [-u] [-i] [-r startPasscode] [-w -|wordlist] [-p progressEach]

 Options:                                                                                  
   -u                 Userland bruteforce method. Requires UID kernel patch, but is much faster (>8 passcodes per second).
   -i                 Don't bruteforce. Read the passcode from stdin and attempt it.
   -r startPasscode   Resume brute force from the specified start passcode.
   -w -|wordlist      Use a wordlist for brute forcing. Use '-' to read from stdin or specify a file path. One passcode per line.
   -p progressEach    Display progress after every specified number of attempts.

 Examples:                                                                                 
   ./bruteforce -u -w wordlist.txt
       Wordlist attack with userland bruteforce mode enabled.

   ./bruteforce -u -p 100                                                    
       Numeric bruteforce attack, starting with 4-digit passcodes before moving onto 5-digit, then 6-digit, etc.

   ./bruteforce -r abc123 -w - < words.txt
       Wordlist attack using Apple keystore starting with the passcode after `abc123` in the words.txt
```

## Supported devices
- (iPhone 2G)
- iPhone 3G
- iPhone 3GS
- iPad 1
- iPhone 4 GSM
- iPhone 4 GSM rev A
- iPhone 4 CDMA

Newer devices are ~~NOT~~ supported as long as you have the correct offsets for each kernel version you run this on.

## Requirements
- Xcode (or Command Line Tools)
- iOS 8.4 SDK
- Mac OS X 10.9 SDK (open Xcode to accept the license agreement)

### Building Ramdisk tools
Run `make` in a `ramdisk_tools` folder 

### SSH access
- Run `./tcprelay.sh` in a new terminal window or use Sliver's 'Relay Device Info'
- Run `ssh -p 2222 root@localhost`
	root password is `alpine`
