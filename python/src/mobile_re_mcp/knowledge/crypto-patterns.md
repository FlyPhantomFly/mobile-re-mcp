# Crypto Patterns

Common cryptographic weaknesses found in Android applications.

---

## Hardcoded Keys and Secrets

### AES Keys
```
# Regex patterns to search for:
AES.*key.*=.*"[0-9a-fA-F]{32,}"
SecretKeySpec\(.*".*"\s*\.getBytes
```
**Risk**: HIGH — hardcoded AES keys allow decryption of all protected data

### API Keys / Tokens
```
# Common variable names:
api_key, apiKey, API_KEY, secret, SECRET, token, TOKEN
Bearer [A-Za-z0-9+/=]{20,}
```
**Risk**: HIGH — exposed API keys may allow backend access

### AWS Credentials
```
AKIA[0-9A-Z]{16}
```
**Risk**: CRITICAL — direct AWS account access possible

---

## Weak Encryption

### ECB Mode
**Pattern**: `Cipher.getInstance("AES/ECB/PKCS5Padding")` or `Cipher.getInstance("AES")`
**Risk**: HIGH — ECB does not hide data patterns; identical plaintext blocks produce identical ciphertext

### Static IV
**Pattern**: `IvParameterSpec(new byte[16])` or `IvParameterSpec("hardcodedIV".getBytes())`
**Risk**: HIGH — static IV with CBC mode makes encryption deterministic

### Weak Key Derivation
**Pattern**: `SecretKeySpec(password.getBytes(), "AES")` — raw password bytes as key
**Risk**: HIGH — no PBKDF2/bcrypt stretching; trivially bruteforceable

### Insecure Random
**Pattern**: `java.util.Random` used for cryptographic values (nonces, IVs, session tokens)
**Risk**: HIGH — `java.util.Random` is not cryptographically secure; use `SecureRandom`

---

## Certificate Issues

### Trust All Certificates
```java
// Pattern:
X509TrustManager with empty checkServerTrusted()
```
**Risk**: CRITICAL — accepts any certificate including self-signed/attacker-controlled

### Hostname Verification Disabled
```java
hostnameVerifier = (hostname, session) -> true;
HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
```
**Risk**: HIGH — allows MITM with any certificate for any hostname

---

## Search Patterns (ripgrep)

```bash
# AES ECB mode
rg "AES/ECB" .

# Hardcoded IV
rg "IvParameterSpec" . -A 2

# Hardcoded key bytes
rg "SecretKeySpec" . -A 2

# Trust all TrustManager
rg "checkServerTrusted" . -A 5

# Hostname bypass
rg "ALLOW_ALL_HOSTNAME_VERIFIER\|HostnameVerifier.*true" .

# Shared preferences storing sensitive data
rg "getSharedPreferences\|putString\|putInt" . -A 3
```
