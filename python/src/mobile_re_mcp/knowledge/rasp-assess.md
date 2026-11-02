# RASP Assessment Protocol

Full assessment protocol for applications protected by enterprise RASP SDKs.

## Step 1 — Identify the RASP

```
rasp_identify(apk_path)
```

Confirm vendor: Guardsquare | Arxan | Promon | Zimperium | custom

## Step 2 — Read the relevant bypass playbook

```
knowledge://bypass-playbooks
```

Find the vendor-specific section and note the escalation order.

## Step 3 — Attempt Level 1 bypass

```
rasp_bypass(rasp_type, "root_detection")
rasp_bypass(rasp_type, "frida_detection")
```

Inject via `frida_spawn(package, script)`. Use hluda if standard frida-server is detected.

## Step 4 — Verify bypass success

Launch the app. If it proceeds past the security check:
- [THINK] Bypass successful at Level 1
- Proceed to SSL pinning bypass: `rasp_bypass(rasp_type, "ssl_pinning")`

If app still blocks:
- [STUCK] Level 1 bypass failed — escalate

## Step 5 — Escalate as needed

Follow the playbook escalation ladder. Document each attempt in memory:
```
memory_write(package, updated_content)
```
Update "Tried and failed" section after each failed attempt.

## Step 6 — Network capture

Once protections are bypassed:
```
mitm_start(8080)
ssl_kill_switch(package)
```
Configure device proxy to host:8080.

## Step 7 — Document

Write final memory with confirmed bypass method, findings, and remaining unknowns.
