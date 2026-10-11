# SentinelIP Browser Sensor

Browser Sensor 01 is an optional Firefox/Chromium WebExtension for safe, structured browser telemetry.

It observes navigation, redirect metadata, boolean login/password-form signals, and safe download metadata. It does not classify websites, block navigation, inspect page contents, or collect credentials.

## Development

Run the isolated tests with:

```text
npm test
```

Load the unpacked `browser-extension/` directory through the browser's extension development page. Configure the options page with a provisioned `BROWSER` sensor, the local SentinelIP API URL, and its token.

The sensor sends authenticated requests to:

```text
POST /telemetry/web
X-SentinelIP-Sensor-ID
X-SentinelIP-Sensor-Token
```

The default privacy mode is `DOMAIN_ONLY`. It removes URL paths, queries, fragments, and userinfo before delivery. The token is stored only in extension-local storage and is never sent to content scripts or included in telemetry payloads.

## Not collected

- Passwords or form values
- Keystrokes
- Page text, HTML, or screenshots
- Cookies or browser storage
- Authentication headers
- Browser fingerprints
- Local file contents or full filesystem paths

Browser Sensor 01 is observational only. Phishing detection, domain intelligence, DNS telemetry, blocking, and threat correlation are deferred.