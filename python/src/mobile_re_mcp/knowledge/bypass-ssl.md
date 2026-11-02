# SSL Pinning Bypass Protocol

## Detection

Look for:
- `CertificatePinner` (OkHttp)
- `checkServerTrusted` with certificate comparison
- `network_security_config.xml` with `<pin-set>`
- Hardcoded certificate bytes in assets

## Bypass Escalation

**Level 1**: `ssl_kill_switch(package)` — inject universal bypass via Frida

**Level 2**: If NSC pinning:
- `apk_decompile(apk_path)` → edit `res/xml/network_security_config.xml`
- Remove `<pin-set>` elements → `apk_rebuild_sign(smali_dir)` → reinstall

**Level 3**: Native SSL bypass — hook `SSL_CTX_set_verify`

**Level 4**: Install mitmproxy cert as system CA (requires root)

**Level 5 (Flutter)**: Use dart-specific Frida script targeting `dart::bin::SSLFilter`

[STUCK] If all levels fail: capture raw traffic with tcpdump and analyse protocol.
