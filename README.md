# Mazoku

An Zygisk Module to intercept ACE requests and effectively replace malicious modifications to a genuine attestation.

## Usage

1. Disable all modules & malicious modifiers towards target app.
2. Install this module & set configuration in `/data/adb/mazoku/spoof_target_libs.txt` with `?` flag (to create hardware backed copy of libraries) or `!` flag (to strictly check for specified hardware backed copy & verify its integrity).
3. Reboot & open target app.
4. Check for hardware copies in `/data/user/0/com.example/files/.mazoku` & compare sha256 of blocks to verify verity of backed copies.
5. Enable your modifiers.

# Notes
- Does not work against system libraries such as libc.so, etc...
- Does not hide itself against the process (Shamiko might help but not a permanent solution, see more about susfs).
- Does not hide modifiers from exposition in target process.
