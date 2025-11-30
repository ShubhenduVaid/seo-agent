#!/usr/bin/env python3
"""Compatibility wrapper for running the SEO Audit Agent CLI."""

from seo_agent.cli import main


if __name__ == "__main__":
    import sys

    sys.exit(main())
