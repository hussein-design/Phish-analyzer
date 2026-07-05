# Installing Phish Analyzer Desktop

## Requirements
- Windows 10 or later (64-bit)
- No Python installation required — everything is bundled inside the installer

---

## Step 1 — Download the installer

Go to the [**Releases page**](../../releases) and download the latest
`PhishAnalyzerSetup-x.x.x.exe` file.

> If your browser warns you about an unknown publisher, click **Keep** (or
> **More info → Run anyway** in Windows SmartScreen). The app is unsigned —
> code-signing certificates cost money. The source code is fully open and
> auditable in this repository.

---

## Step 2 — Run the installer

Double-click `PhishAnalyzerSetup-x.x.x.exe`.

- The installer does **not** require administrator rights for a per-user
  install. If prompted, you can choose either your user folder or Program Files.
- A Start Menu shortcut and an optional Desktop shortcut are created.
- An uninstaller is registered in Windows **Apps & features**.

---

## Step 3 — Launch and analyse an email

Open **Phish Analyzer Desktop** from the Start Menu or Desktop.

1. Drag and drop a `.eml` file onto the drop zone, or click **Browse**.
2. The app analyses the email in seconds and shows a verdict (Benign /
   Suspicious / Phishing) with a full breakdown of every signal detected.
3. Click **Report** to see the detail view, or **Export DOCX** to save a
   formatted Word report.

---

## Optional — Add API keys for richer analysis

The app works out of the box **without** any API keys. The analysis engine
checks headers, sender domain, URL patterns, attachment extensions, and body
language entirely offline.

For enhanced threat intelligence:

| Service | What it adds | Free tier |
|---|---|---|
| [VirusTotal](https://www.virustotal.com/gui/join-us) | URL/domain reputation from 70+ AV engines | 500 lookups/day |
| [AbuseIPDB](https://www.abuseipdb.com/register) | Sender IP abuse reputation | 1 000 checks/day |

To enter your keys: click the **⚙ Settings** button in the toolbar, paste
your keys, and click **Save**. Keys are stored locally in your user profile —
they are never sent anywhere other than the respective API service.

---

## Updating

Download the new installer from the Releases page and run it — it upgrades
in place. Your analysis history and settings are stored in
`%LOCALAPPDATA%\PhishAnalyzerDesktop\PhishAnalyzerDesktop\` and are
preserved across upgrades and uninstalls.

## Uninstalling

Open Windows **Settings → Apps → Apps & features**, search for
*Phish Analyzer Desktop*, and click **Uninstall**.  
Your data in `%LOCALAPPDATA%\PhishAnalyzerDesktop\` is left intact; delete
that folder manually if you want a clean removal.
