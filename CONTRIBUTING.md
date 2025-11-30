# Contributing to SEO Audit Agent

Thanks for your interest in improving the project! Contributions of all kinds are welcome, including bug reports, documentation improvements, and new features that align with the tool's lightweight scope.

## Ways to contribute
- Report bugs with clear reproduction steps and the URL/goal you tested.
- Propose features or heuristics that make the audit more useful.
- Improve documentation, examples, or developer ergonomics.
- Submit code changes that stay dependency-free (standard library only).

## Development setup
1. Install Python 3.9 or newer.
2. Clone the repository and create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   python3 -m pip install --upgrade pip
   ```
   No extra packages are required.
3. Run the CLI locally to verify behavior:
   ```bash
   python3 seo_agent.py https://example.com --goal "traffic growth"
   ```

## Pull request guidelines
- Keep changes focused and include context on what is being improved.
- Add or update tests when you introduce new logic. If a unit test is not practical, include a manual test note in the PR description.
- Update documentation (README, examples, changelog entries) when behavior changes.
- Follow PEP 8 style, use type hints, and prefer small, readable functions.
- Do not add external dependencies unless discussed and justified.

## Issue guidelines
- Include the command you ran, the URL audited, and any error output.
- Describe the expected vs. actual result; attach a snippet of the report if relevant.
- For security concerns, use the process described in `SECURITY.md` instead of filing a public issue.

## Code of Conduct

By participating, you agree to uphold the standards in `CODE_OF_CONDUCT.md`. Be respectful and assume good intent.
