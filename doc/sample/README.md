# Sample report — synthetic OpenLDAP log

[`slaplog-sample.html`](slaplog-sample.html) is a complete HTML report generated
by slaplog from a synthetic log. It is here to show what the tool produces and
how a report reads.

**All data is fictional.** The log uses reserved names only:

- domain `dc=example,dc=com` (RFC 2606);
- addresses from the RFC 5737 documentation ranges (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`).

No production identity, hostname, address or directory content appears here.

## What the sample shows

The generated log spans four days and tells a small incident story:

- `portal`, `monitor`, `legacy-app` and `admin` run normally;
- `hr-sync` bursts heavily at 02:00–03:00 every night;
- on **2026-09-16 10:00** a new service, `reporting`, starts and becomes the
  busiest consumer, running expensive substring and negated searches.

The report picks this up:

- **Top Consumer per Hour** — the bars turn from green/orange to blue at
  10:00 on 16 September;
- **Consumers Over Time (stacked)** — how each hour's total load is split;
- a vertical **onset** marker at 2026-09-16 10:00 on both charts, with a
  tooltip explaining it;
- a **resource hog** verdict for the unindexed filter family.

## Files

| File | Purpose |
|---|---|
| `slaplog-sample.html` | The generated report — open it in a browser. |
| `access.log.gz` | The synthetic log it was generated from. |
| `make_sample.py` | Deterministic generator (seed 42). |

## Regenerate

From this directory:

```sh
python3 make_sample.py access.log
gzip -9 -c access.log > access.log.gz
../../slaplog access.log.gz -o html \
    --title "slaplog sample (synthetic data)" \
    > slaplog-sample.html
```

The generator is deterministic, so the same log — and the same report — come
back on every run.
