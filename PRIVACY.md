# Privacy Policy for BlueDragon Web Security

**Last updated: December 2024**

## Overview

BlueDragon Web Security is a browser extension designed for security researchers, bug bounty hunters, and red teamers. This privacy policy explains how the extension handles data.

## Data Collection

### What We DO NOT Collect

- We do **not** collect any personal information
- We do **not** send any data to external servers owned by us
- We do **not** track your browsing history
- We do **not** use analytics or telemetry
- We do **not** store any data outside your browser

### What the Extension Stores Locally

The extension stores the following data **locally in your browser** using Chrome's storage API:

- **Settings**: Your configuration preferences (auto-scan enabled, scan mode, notification settings)
- **History**: Scan results and detected vulnerabilities (stored locally for your reference)
- **Reviewed findings**: Which vulnerabilities you've marked as reviewed

This data never leaves your browser unless you explicitly export it.

## Data Processing

### Framework Detection

The extension analyzes web pages you visit to detect frontend frameworks (Next.js, Angular, SvelteKit, Nuxt, etc.) and their versions. This analysis happens **entirely within your browser** - no data is sent to external servers.

### Vulnerability Scanning

When you run a scan, the extension:

- Checks detected framework versions against a local CVE database
- Performs safe, non-destructive probing of potential vulnerabilities
- Rate-limits requests (max 5/second) to avoid impacting target systems
- Never probes sensitive endpoints (payment, billing, authentication)

All scanning happens directly from your browser to the target website you're testing.

### DNS-Based Validation (Optional)

Some vulnerability checks use out-of-band validation via services like Burp Collaborator or Interactsh. When enabled:

- Requests go directly from your browser to the target and validation service
- You control the validation server configuration
- No data passes through our servers

## Permissions Explained

| Permission | Why It's Needed |
|------------|-----------------|
| `activeTab` | Access the current tab to scan for vulnerabilities |
| `scripting` | Inject content scripts to analyze page frameworks |
| `storage` | Save your settings and scan history locally |
| `notifications` | Alert you when vulnerabilities are found |
| `webRequest` | Monitor network requests to detect vulnerable patterns |
| `webNavigation` | Track page loads for auto-scan functionality |
| `tabs` | Access tab URLs for targeted scanning |
| `<all_urls>` | Scan websites you choose to analyze |

## Third-Party Services

The extension does not integrate with any third-party analytics, advertising, or tracking services.

## Data Security

- All data is stored locally using Chrome's secure storage API
- No external transmission of your data occurs
- You can clear all stored data at any time through Chrome's extension settings

## Your Rights

You have full control over your data:

- **Export**: Download your scan history as JSON, Markdown, or Nuclei templates
- **Delete**: Clear all data via Chrome settings (Settings > Extensions > BlueDragon > Clear data)
- **Disable**: Turn off features like auto-scan or notifications at any time

## Changes to This Policy

We may update this privacy policy occasionally. Changes will be reflected in the "Last updated" date.

## Contact

For questions about this privacy policy or the extension:

- GitHub Issues: [https://github.com/fbettag/bluedragon-web-security/issues](https://github.com/fbettag/bluedragon-web-security/issues)
- Author: [fbettag](https://github.com/fbettag)

## Open Source

BlueDragon Web Security is open source under the MIT License. You can review the complete source code at:

[https://github.com/fbettag/bluedragon-web-security](https://github.com/fbettag/bluedragon-web-security)
