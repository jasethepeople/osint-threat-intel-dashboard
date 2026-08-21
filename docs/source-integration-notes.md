# Source Integration Notes

The ingestion layer will use source-specific adapters and persist a normalized, provenance-preserving record before any enrichment. The National Vulnerability Database exposes the CVE 2.0 endpoint at `https://services.nvd.nist.gov/rest/json/cves/2.0` and requires offset pagination through `startIndex` and `resultsPerPage`; the adapter will advance from a stored source cursor, use a bounded modified-date window, and preserve NVD identifiers, descriptions, CVSS metrics, CPE-derived stack hints, and source timestamps.[1]

GitHub’s public Global Security Advisories endpoint is available at `GET /advisories` without authentication for public resources. It supports updated/published time filters, ecosystem and severity filters, cursor pagination, and up to 100 items per page. The adapter will use incremental `updated` windows plus a stored high-water mark; it will retain `ghsa_id`, `cve_id`, affected package ecosystems, CVSS, EPSS, summary, description, and advisory provenance.[2]

RSS entries are normalized as news-derived intelligence rather than asserted vulnerability facts. The initial curated feeds are SecurityWeek’s public RSS endpoint, `https://www.securityweek.com/feed/`, and The Hacker News public RSS endpoint, `https://feeds.feedburner.com/TheHackersNews`. Their titles, summaries, canonical URLs, publication dates, authors when supplied, and declared publisher are retained, while text-derived CVEs, geographic mentions, and zero-day terms remain explicitly marked as extraction results with confidence and provenance.[4] [5]

## References

[1]: https://nvd.nist.gov/developers/vulnerabilities "NVD Vulnerability APIs"
[2]: https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28 "GitHub REST API: Global Security Advisories"
[4]: https://feeds.feedburner.com/TheHackersNews "The Hacker News RSS"
[5]: https://www.securityweek.com/feed/ "SecurityWeek RSS"
