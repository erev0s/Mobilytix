# Test APKs

Place test APKs in this directory. The `scripts/setup.sh` script will
automatically download them.

## Recommended test APKs

| APK | Purpose | Source |
|-----|---------|--------|
| **DIVA** (Damn Insecure and Vulnerable App) | Basic vulnerability scanning | [payatu/diva-android](https://github.com/payatu/diva-android/releases) |
| **InsecureBankv2** | Full pentest (static + dynamic) | [dineshshetty/Android-InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2/releases) |

## Manual download

```bash
# DIVA
curl -fsSLo diva-beta.apk \
  https://github.com/payatu/diva-android/releases/download/v1.0/diva-beta.apk

# InsecureBankv2
curl -fsSLo InsecureBankv2.apk \
  https://github.com/dineshshetty/Android-InsecureBankv2/releases/download/v2.3.2/InsecureBankv2.apk
```
