# MintAuth

A Minecraft Java mod for AutoMint accounts and SSID login.

**[Download MintAuth](https://automint.online/download/mintauth)** · [AutoMint](https://automint.online)

## Features

- Sign in to your Mint accounts without copying SSIDs.
- Add your own SSIDs and choose whether to sync them with AutoMint.
- Switch accounts from one menu, or return to your launcher account.
- Refresh sessions automatically for eligible Mint accounts.
- Share an encrypted account library between Minecraft installations on your device.
- Open AutoMint to secure a new account directly from the mod.
- Turn Mint-themed menus on or off.
- Receive signed updates automatically.
- Revoke linked devices from AutoMint’s security settings.

## Get started

1. Download the JAR matching your Minecraft version and put it in your instance’s `mods` folder.
2. Open **MintAuth** in Minecraft, then choose **Link AutoMint** or **Use an SSID**.
3. Choose an account and play. Leave your current world or server before switching accounts.

Official downloads and website-connected features require **SUPPORT+**. Manual SSID login works without linking AutoMint.

## Versions

| Minecraft | Loader | Java |
| --- | --- | --- |
| 1.8.9 | Forge | 8 |
| 1.21.11 | Fabric + Fabric API | 21 |
| 26.3 | Fabric + Fabric API | 25 |

## Build and run

For authorized builds on **Windows**, install **Git** and **PowerShell 7**, then run from the repository root:

```powershell
pwsh -File ./scripts/install-jdks.ps1
pwsh -File ./scripts/build.ps1
```

The scripts set up local JDKs and Gradle, run core tests, and build the adapters. To run only the core tests, use `pwsh -File ./scripts/build.ps1 -Target core`.

After a successful build, take the final JAR from `<target>/build/libs/` and add it to a matching Prism instance’s `mods` folder. Install Forge or Fabric with Fabric API as listed above, then launch the instance. Use the JAR without a `-thin`, `-bundled`, `-dev`, or `-sources` suffix.

**Current limitation:** adapter builds need reviewed dependency-metadata fixes; this snapshot also omits branding assets. See the source notes below. Keep dependency verification enabled.

<details>
<summary>About this source repository</summary>

Text-only review snapshot; binary assets and Gradle wrappers are omitted. Core tests and a local Forge build passed. Clean-runner adapter verification still needs reviewed dependency metadata, including Fabric’s checkout-dependent generated artifacts. Public CI covers core and release-security tests.

First-party files, including `signing/jar-signing.crt` and `signing/release-public.pub`, use the [custom license](LICENSE). Those two public verification files retain their encoded contents; their licensing is recorded here. Third-party terms are retained in [NOTICE](NOTICE) and the bundled license texts.

</details>

**Source-available:** viewing source and using official JARs are permitted; personal builds, modifications and redistribution require permission. See [LICENSE](LICENSE).

[Contact & private security reports](mailto:contact@hilfing.dev)

Copyright (c) 2026 AutoMint. Not an official Mojang or Microsoft product.
