# BetterCut

BetterCut is a network-control app for rooted Android devices. See who is connected
to your Wi-Fi, temporarily block a device's internet access, or set a speed limit
from your phone.

## Download

**[Download the latest APK](https://github.com/nhCoder/BetterCut/releases/latest)**

Open the latest release, expand **Assets**, and download **BetterCut.apk**.
Open the APK on your phone and allow installation from your browser or file manager if prompted.

Requires **Android 7.0+** and **root access** for network control.
One APK supports ARM32, ARM64, x86, and x86_64. Compatibility depends on your device and network.

## What it does

- **Discover devices:** scan the local network and show IP addresses, MAC addresses,
  device names, and manufacturer information when available.
- **Block or limit connections:** cut internet access or choose a speed limit for
  an individual device, with bulk controls for multiple devices.
- **Protect selected devices:** add devices to the whitelist to exclude them from
  blocking and throttling. Your phone and the gateway are also excluded.
- **View live traffic:** start a traffic-monitoring session for a selected device
  to see upload and download activity.
- **Restore access:** remove limits for a device or use **Restore all** to end
  active restrictions.

## How it works

Connect your rooted phone to the same Wi-Fi network as the devices you want to
manage, open BetterCut, and grant root access. The app scans the local IPv4
network and lists the devices it finds. Select a device to block its connection,
adjust its speed, or view its traffic.

Under the hood, BetterCut uses **ARP spoofing**: it changes where selected devices
send traffic intended for the router. Blocking interrupts that path; speed limits
route traffic through your phone and use its firewall to limit the flow. Restoring
access removes BetterCut's rules and sends corrective ARP messages to restore the
normal route. It does not change your router's settings.

Controls apply to local IPv4 traffic, not IPv6. Network isolation, ARP protection,
and device security policies can prevent them from working. Speed limits are
approximate, and live traffic monitoring is a separate session that replaces
active restrictions.

## Releases

Maintainers: open **Actions → Release APK → Run workflow**, enter a new tag
(for example, `v1.1.0`) and an increasing version code, then run it.
The workflow builds a signed APK and publishes it to **[Releases](https://github.com/nhCoder/BetterCut/releases)**.

[One-time signing setup](.github/RELEASING.md)
