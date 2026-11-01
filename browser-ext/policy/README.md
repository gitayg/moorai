# Browser Guard: managed force-install

Templates for installing MoorAI Browser Guard on every managed Chrome and Edge browser and setting its
console URL, install token and mode by policy. Render them with the extension id:

```
node scripts/browser-ext-policy.mjs --id <32-letter id> --out ./policy-out \
  --server-url https://console.example.com --install-token <token> --mode coach [--lock]
```

The id is assigned when the extension is published to the Chrome Web Store and Edge Add-ons (the owner's
step; the two stores assign different ids, so render once per id). For a self-hosted build, add
`--update-url https://<your host>/updates.xml`; browsers accept an off-store force-install only on
domain-joined Windows and MDM-managed macOS.

| File | Where it goes |
|---|---|
| `chrome-macos.mobileconfig`, `edge-macos.mobileconfig` | MDM configuration profile (Jamf, Kandji, Intune macOS custom profile). Sets `ExtensionInstallForcelist` in `com.google.Chrome` / `com.microsoft.Edge` and the managed settings in `<domain>.extensions.<id>`. |
| `chrome-windows.reg`, `edge-windows.reg` | `HKLM\SOFTWARE\Policies\<vendor>\ExtensionInstallForcelist` plus `...\3rdparty\extensions\<id>\policy`. Import by GPO preference, a script, or your RMM. Value `"1"` must not collide with a force-list entry you already deploy (`--index N`). |
| `chrome-linux-policy.json` | `/etc/opt/chrome/policies/managed/` (Chromium: `/etc/chromium/policies/managed/`). |
| `moorai-browser-guard.admx`, `en-US/moorai-browser-guard.adml` | `C:\Windows\PolicyDefinitions` (or the central store) for GPO, or Intune "Imported Administrative templates". Covers the managed settings; force-install itself uses the browsers' own ADMX policy "Configure the list of force-installed apps and extensions". |

## Intune

- **Windows:** in a Settings catalog profile, set Google Chrome (or Microsoft Edge) > Extensions >
  "Configure the list of force-installed apps and extensions" to `<id>;<update URL>`. Import
  `moorai-browser-guard.admx` / `.adml` under Devices > Configuration > Import ADMX, then create an
  "Imported Administrative templates" profile for the console URL, token and mode.
- **macOS:** Devices > Configuration > Create > macOS > Templates > Custom, upload the rendered
  `.mobileconfig`.

## Reporting from a force-installed copy

The extension posts signals from its background worker, which needs host permission for the console origin.
A store build asks the user for it on the options page, and a browser policy cannot grant it. For
reporting with no user step, publish a self-hosted build that carries the origin:
`node scripts/browser-ext-package.mjs --console-origin https://console.example.com`.

## Checked against

- Chrome: `ExtensionInstallForcelist` value format `<id>;<update URL>`, store update URL
  `https://clients2.google.com/service/update2/crx`; extension policy under
  `HKLM\Software\Policies\Google\Chrome\3rdparty\extensions\<id>\policy`, macOS domain
  `com.google.Chrome.extensions.<id>`, Linux `3rdparty.extensions.<id>` (Chromium "Configuring policy for
  extensions").
- Edge: `SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist`, update URL
  `https://edge.microsoft.com/extensionwebstorebase/v1/crx` (Microsoft Learn, ExtensionInstallForcelist).
  The Edge `3rdparty\extensions\<id>\policy` registry path and the `com.microsoft.Edge.extensions.<id>`
  macOS domain follow the Chromium layout and are reported to work by Edge administrators; Microsoft Learn
  has no page for them. Confirm on a pilot device with `chrome.storage.managed` before a fleet rollout.
