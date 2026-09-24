# Release setup

Add these repository secrets under **Settings → Secrets and variables → Actions**:

| Secret | Value |
| --- | --- |
| `ANDROID_KEYSTORE_BASE64` | Your release keystore encoded as Base64 |
| `ANDROID_KEYSTORE_PASSWORD` | Keystore password |
| `ANDROID_KEY_ALIAS` | Signing key alias |
| `ANDROID_KEY_PASSWORD` | Signing key password |

Use the same signing key for every release so users can install updates.
Keep the keystore and passwords out of the public repository, including its history.

Push the workflow to the default branch. In **Actions → Release APK → Run workflow**,
select the branch to release, enter a version such as `1.0.0` or `v1.0.0` and a version
code higher than the previous release (`1` for your first release). Both version formats
produce a `v1.0.0` tag, which must not already exist. The workflow tests and builds a universal
release APK, then publishes `BetterCut.apk` and its SHA-256 checksum.

For local builds, install Go 1.24+ and the Android build tools, then run
`./gradlew assembleDebug`. Add `-PandroidAbis=x86_64` to target one architecture.
