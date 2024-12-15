# Mazoku

An Zygisk Module to intercept ACE requests and effectively replace malicious modifications to a genuine attestation.

## Current supported versions
- CODM 1.0.48 (Working as of now/Current state of the source code)

## Requirments

To build this project you need to :
- have the target app to use external objects or simply check presence of `[anon:object_external_alloc]` in `/proc/self/maps` of target app.
- have the necessary offsets:
  - GetExternalObjects
  - CreateSWBackedIntegrity
  This part can be ignored if your target app isn't totally caring about updating its ACE backend (comm/mua).
  - Treaters
  - CustomCall
  - Param
- have the objects that are suspected for target scans.
- have the necessary patches to override the responses.

More guide to how to obtain these will be available soon.

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
