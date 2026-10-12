# Authorized small public CIDRs (09D.6)

A user must validate a range, review its canonical CIDR and address count, and explicitly confirm authorization for every address. Preview performs no DNS lookup, scan, or database write. Creation validates the range again and stores its exact membership atomically with its PUBLIC_CIDR scope.

Only IPv4 /29, /30, /31, and /32 scopes are eligible: at most eight addresses. Every address passes the existing single-public-IPv4 policy. Mixed/special-purpose ranges fail closed. Input with host bits is normalized using strict=False; the canonical range is shown before confirmation.

**Enumeration includes every address in the CIDR**, including both endpoints: /29 = 8, /30 = 4, /31 = 2, /32 = 1. This is authorization of an address block, not an assumption about which addresses are hosts on a particular subnet. Scope-specific device identity is retained even if scopes overlap.

Scan requests reference only a persisted scope ID. Authorization metadata, enabled state, canonical range, size, and persisted membership are validated before scanning. Each concrete address is sent sequentially to the existing public IPv4 host/service scanner methods. CIDR text never reaches Nmap. Flags, port list, retries, and per-command timeouts are unchanged. The eight-address worst-case command timeout budget is up to ten minutes (8 × [30 + 45 seconds]); an error stops further enumeration, retaining evidence already saved. No worker, polling, automatic retry, or automatic scan is added.

Migration 29 adds a small membership table and extends device membership triggers. It does not rewrite scopes, devices, findings, or CVE records or authorize any legacy inert CIDR record. Existing scopes and their identity are preserved.

Verification uses synthetic authorization fixtures and mocked subprocess calls. Addresses in tests are never scanned. Existing deterministic findings and CVE review remain observational assessments, not exploitation or compromise claims.
