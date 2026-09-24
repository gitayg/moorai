# Multilingual injection fixtures

One JSON file per language, named after its key in `INJECTION_I18N_BY_LANG`
(`data/injection-i18n.js`), e.g. `hebrew.json`, `norwegian-danish.json`.

```json
{
  "language": "hebrew",
  "reviewedBy": "who reviewed these phrases",
  "override": ["phrases that must raise the instruction-override finding"],
  "reveal": ["phrases that must raise the reveal-system-prompt finding"],
  "negatives": ["ordinary text that must raise no multilingual finding"]
}
```

`test/i18n-fixtures.test.mjs` runs every file through the detection engine:

| List | prompt / file / index | output | tool |
|---|---|---|---|
| `override` | `inj-multilingual` (#3) | `inj-multilingual-untrusted` (#40) | `mcp-tool-poisoning-i18n` (#60) |
| `reveal` | `inj-multilingual` (#3) | no i18n finding | no i18n finding |
| `negatives` | no i18n finding | no i18n finding | no i18n finding |

`language` must equal the file name, and `reviewedBy` must be non-empty. Any list may be empty.

## Who writes the phrases

Phrases are supplied and reviewed by a native speaker of the language, and `reviewedBy` names them.
A phrase written by someone who does not speak the language measures only what that person expected
the pattern to match. The negatives matter as much as the positives: they should be ordinary text
that talks about instructions, rules, prompts or the system without overriding anything.

`hebrew.json` is a subset of `test/hebrew-injection.test.mjs`, copied verbatim.

`node scripts/i18n-coverage.mjs` shows which languages have a fixture file.
