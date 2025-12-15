from __future__ import annotations

import json

from seo_agent.models import AuditContext, Issue

from .html import extract_schema_types
from .types import CheckEnv


def check_schema(context: AuditContext, _env: CheckEnv) -> list[Issue]:
    analyzer = context.analyzer
    issues: list[Issue] = []
    if not analyzer.ld_json_blocks:
        issues.append(
            Issue(
                id="content.structured_data_missing",
                severity="important",
                category="content",
                title="Structured data is missing",
                what="No JSON-LD structured data detected; rich results eligibility is limited.",
                steps=[
                    "Add JSON-LD schema matching the page type (Article, Product, Organization, Breadcrumb).",
                    "Validate required and recommended fields per schema.org and Google guidelines.",
                    "Keep schema in sync with on-page content to avoid manual actions.",
                ],
                outcome="Eligibility for rich snippets, improved CTR, and clearer entity understanding.",
                validation="Run the URL through Google's Rich Results Test and fix any errors.",
                impact="medium",
                effort="medium",
                confidence="high",
                evidence={"ld_json_blocks": 0},
            )
        )
        return issues

    invalid_blocks = 0
    missing_type_blocks = 0
    for block in analyzer.ld_json_blocks:
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError:
            invalid_blocks += 1
            continue
        types = extract_schema_types(parsed)
        if not types:
            missing_type_blocks += 1

    if invalid_blocks:
        issues.append(
            Issue(
                id="content.structured_data_invalid_json",
                severity="important",
                category="content",
                title="Structured data could not be parsed",
                what=f"{invalid_blocks} JSON-LD block(s) failed to parse; invalid schema will be ignored.",
                steps=[
                    "Validate JSON-LD syntax (quotes, commas, braces) and escape characters correctly.",
                    "Run the page through Rich Results Test to pinpoint errors.",
                    "Keep schemas small and focused on the page type.",
                ],
                outcome="Valid structured data that search engines can process.",
                validation="Re-run Rich Results Test; ensure no syntax errors remain.",
                impact="medium",
                effort="medium",
                confidence="high",
                evidence={"invalid_blocks": invalid_blocks},
            )
        )
    if missing_type_blocks:
        issues.append(
            Issue(
                id="content.structured_data_missing_type",
                severity="recommended",
                category="content",
                title="Structured data missing @type",
                what=f"{missing_type_blocks} JSON-LD block(s) lacked an @type; search engines may ignore them.",
                steps=[
                    "Add an explicit @type (e.g., Article, Product, Organization) to each JSON-LD object.",
                    "Ensure nested graphs also declare types.",
                    "Keep schema aligned with the visible content.",
                ],
                outcome="Structured data is eligible for rich result interpretation.",
                validation="Validate with Rich Results Test and confirm @type is present.",
                impact="low",
                effort="low",
                confidence="high",
                evidence={"missing_type_blocks": missing_type_blocks},
            )
        )
    return issues
