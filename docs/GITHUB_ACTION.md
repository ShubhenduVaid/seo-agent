# GitHub Action

Use the official GitHub Action to run audits in CI and publish a job summary.

## Basic usage

```yaml
name: SEO Audit

on:
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ShubhenduVaid/seo-agent@v0
        with:
          url: https://example.com
          goal: traffic growth
          format: github
          fail_on_critical: true
          extra_args: --crawl-depth 1 --crawl-limit 5 --crawl-exclude "/search*"
```

The action writes the report output to the GitHub job summary when `write_summary` is `true` (default).

## Inputs

- `url` (required): URL to audit.
- `goal`: Primary goal for the audit.
- `format`: Output format (`text`, `markdown`, `json`, `sarif`, `github`). Default: `github`.
- `config`: Path to an INI config file.
- `report`: Optional path to write the report output.
- `extra_args`: Additional CLI args to pass through (quoted string).
- `fail_on_critical`: Fail the job when critical issues exist. Default: `false`.
- `write_summary`: Append stdout to `GITHUB_STEP_SUMMARY`. Default: `true`.
- `quiet`: Pass `--quiet` to suppress prompts. Default: `true`.
- `python_version`: Python version to install. Default: `3.11`.

## SARIF upload example

```yaml
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ShubhenduVaid/seo-agent@v0
        with:
          url: https://example.com
          format: sarif
          report: ./reports/seo.sarif
          write_summary: false
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./reports/seo.sarif
```

## Tips

- Use `extra_args` to pass crawl filters and limits (e.g., `--crawl-include "/blog/*"`).
- Use `format: github` to produce a concise summary for job output.
