# Stuck Protocol

Use this when a bypass attempt has failed and you are blocked.

## Step 1 — Document what failed

Update memory using `memory_write`:
- What was tried (exact script / technique)
- What happened (crash, detection, kill, silent failure)
- Which level of the escalation ladder you are on

## Step 2 — Gather more information

- `adb_logcat_read(200)` — look for security SDK log messages
- `adb_shell("logcat -d | grep -i zimper\|guard\|promon\|detect")` — filter security events
- Check if app continues running or kills itself (different implications)

## Step 3 — Re-read knowledge

- `knowledge://detection-patterns` — did you miss a detection vector?
- `knowledge://bypass-playbooks` — is there a higher escalation level?

## Step 4 — Alternative approach

Choose one:
A. Switch to static-only analysis — extract as much as possible from decompiled code
B. Use a non-rooted device with frida gadget embedded in APK
C. Binary patch the native library protection routine (advanced)
D. Use a different version of the app (older versions may have fewer protections)

## Step 5 — Update hypothesis

Write your new hypothesis in memory and state the next specific action.

[DONE] You are no longer stuck when you have a clear next action.
