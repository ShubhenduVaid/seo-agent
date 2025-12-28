# Integrations (Offline)

SEO Audit Agent does not call external APIs. Instead, you can enrich reports using local exports from existing tools.

## PageSpeed or Lighthouse JSON

Use `--psi-json` to attach performance metrics from a PageSpeed Insights or Lighthouse JSON export.

```bash
seo-agent https://example.com --psi-json ./lighthouse.json
```

Notes:
- The file can be a Lighthouse report (from Chrome DevTools or Lighthouse CLI) or a PageSpeed Insights JSON export.
- Metrics extracted include performance score, FCP, LCP, CLS, TBT, INP, and Speed Index.

## Search Console Pages CSV

Use `--gsc-pages-csv` to weight priorities using Search Console data.

```bash
seo-agent https://example.com --gsc-pages-csv ./gsc-pages.csv
```

Expected columns (case-insensitive; variants supported):
- page or url
- clicks (optional)
- impressions (optional)
- ctr (optional; percent allowed)
- position or average position (optional)

Export steps (Google Search Console):
1. Performance -> Search results
2. Switch to the Pages tab
3. Click Export -> CSV

The agent aggregates metrics per canonical page path and boosts issue impact for pages with high impressions.
