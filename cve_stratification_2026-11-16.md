# CVE stratification — 365 days to 2026-11-16

Built by `cve_strata.py report` from `data/cve_strata.csv.gz` (last synced with NVD 2026-11-16T22:44:43 UTC, table floor 2025-11-16). **Published**: 107,834 CVEs with an NVD publication date in (2025-11-16, 2026-11-16]. **KEV additions**: 321 CVEs CISA added in the same window, whatever their publication date; 246 of them were also published in it. *Per 1,000 published* divides the two, the stratified analogue of the model's conversion; *lift* is a class's share of KEV additions over its share of publications.

## Coverage of each field

| field | published in window | KEV additions |
|---|---:|---:|
| vendor from NVD CPE applicability | 42.9% | 100.0% |
| vendor from the assigner's `affected` block | 49.5% | 0.0% |
| any vendor | 92.3% | 100.0% |
| CVSS vector (exposure class) | 93.7% | 100.0% |
| … scored by NVD itself | 7.8% | 23.1% |
| weakness type (CWE) | 90.5% | 99.4% |
| SSVC decision points (CISA) | 90.6% | 100.0% |

## By exposure class

| exposure (CVSS) | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| remote, no privileges, no user action | 33,388 | 31.0% | 185 | 57.6% | 5.5 | 1.9× | 152 |
| remote, other | 47,239 | 43.8% | 87 | 27.1% | 1.8 | 0.6× | 60 |
| local or physical | 20,383 | 18.9% | 49 | 15.3% | 2.4 | 0.8× | 34 |
| unscored | 6,824 | 6.3% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,834 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## By vendor: the 20 with most KEV additions, and the rest

Vendors are chosen by exploitation, not volume. Rates for vendors whose CVEs are often unanalyzed are overstated to the extent their publications sit in *(no vendor recorded)*.

| vendor | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| microsoft | 5,668 | 5.3% | 42 | 13.1% | 7.4 | 2.5× | 29 |
| cisco | 406 | 0.4% | 22 | 6.9% | 54.2 | 18.2× | 20 |
| apple | 1,260 | 1.2% | 12 | 3.7% | 9.5 | 3.2× | 7 |
| google | 4,935 | 4.6% | 12 | 3.7% | 2.4 | 0.8× | 12 |
| fortinet | 256 | 0.2% | 11 | 3.4% | 43.0 | 14.4× | 11 |
| linux | 9,322 | 8.6% | 8 | 2.5% | 0.9 | 0.3× | 4 |
| ivanti | 65 | 0.1% | 8 | 2.5% | 123.1 | 41.3× | 8 |
| adobe | 1,269 | 1.2% | 7 | 2.2% | 5.5 | 1.9× | 5 |
| oracle | 4,154 | 3.9% | 6 | 1.9% | 1.4 | 0.5× | 3 |
| sonicwall | 53 | 0.0% | 6 | 1.9% | 113.2 | 38.0× | 6 |
| citrix | 45 | 0.0% | 6 | 1.9% | 133.3 | 44.8× | 6 |
| synacor | 25 | 0.0% | 5 | 1.6% | 200.0 | 67.2× | 3 |
| vmware | 195 | 0.2% | 5 | 1.6% | 25.6 | 8.6× | 3 |
| langflow | 218 | 0.2% | 5 | 1.6% | 22.9 | 7.7× | 5 |
| paloaltonetworks | 112 | 0.1% | 5 | 1.6% | 44.6 | 15.0× | 5 |
| checkpoint | 23 | 0.0% | 5 | 1.6% | 217.4 | 73.0× | 5 |
| gitlab | 271 | 0.3% | 4 | 1.2% | 14.8 | 5.0× | 2 |
| solarwinds | 48 | 0.0% | 4 | 1.2% | 83.3 | 28.0× | 3 |
| arista | 9 | 0.0% | 4 | 1.2% | 444.4 | 149.3× | 4 |
| jfrog | 45 | 0.0% | 4 | 1.2% | 88.9 | 29.9× | 4 |
| (other vendors) | 71,193 | 66.0% | 140 | 43.6% | 2.0 | 0.7× | 101 |
| (no vendor recorded) | 8,262 | 7.7% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,834 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## Vendor × exposure: KEV additions / published, per 1,000

| vendor | remote, no privileges, no user action | remote, other | local or physical | unscored |
|---|---:|---:|---:|---:|
| microsoft | 10/775 = 12.9 | 16/1,682 = 9.5 | 16/3,211 = 5.0 | — |
| cisco | 16/200 = 80.0 | 3/170 = 17.6 | 3/36 = 83.3 | — |
| apple | 1/279 = 3.6 | 5/268 = 18.7 | 6/713 = 8.4 | — |
| google | 1/276 = 3.6 | 8/3,827 = 2.1 | 3/832 = 3.6 | — |
| fortinet | 9/91 = 98.9 | 2/139 = 14.4 | 0/26 = 0.0 | — |
| linux | 1/1,190 = 0.8 | 0/118 = 0.0 | 7/4,270 = 1.6 | 0/3,744 = 0.0 |
| ivanti | 5/17 = 294.1 | 2/38 = 52.6 | 1/10 = 100.0 | — |
| adobe | 3/162 = 18.5 | 2/543 = 3.7 | 2/564 = 3.5 | — |
| oracle | 5/1,350 = 3.7 | 0/2,214 = 0.0 | 1/590 = 1.7 | — |
| sonicwall | 3/15 = 200.0 | 2/30 = 66.7 | 1/8 = 125.0 | — |
| citrix | 6/33 = 181.8 | 0/1 = 0.0 | 0/11 = 0.0 | — |
| synacor | 2/1 = 2000.0 | 3/24 = 125.0 | — | — |
| vmware | 4/101 = 39.6 | 1/79 = 12.7 | 0/15 = 0.0 | — |
| langflow | 3/62 = 48.4 | 2/154 = 13.0 | 0/2 = 0.0 | — |
| paloaltonetworks | 4/38 = 105.3 | 1/34 = 29.4 | 0/40 = 0.0 | — |
| checkpoint | 4/14 = 285.7 | 0/4 = 0.0 | 1/5 = 200.0 | — |
| gitlab | 4/47 = 85.1 | 0/223 = 0.0 | 0/1 = 0.0 | — |
| solarwinds | 4/11 = 363.6 | 0/34 = 0.0 | 0/3 = 0.0 | — |
| arista | 3/3 = 1000.0 | 1/6 = 166.7 | — | — |
| jfrog | 2/6 = 333.3 | 2/38 = 52.6 | 0/1 = 0.0 | — |
| (other vendors) | 95/26,126 = 3.6 | 37/35,362 = 1.0 | 8/9,609 = 0.8 | 0/96 = 0.0 |
| (no vendor recorded) | 0/2,591 = 0.0 | 0/2,251 = 0.0 | 0/436 = 0.0 | 0/2,984 = 0.0 |

## By weakness type: the 15 with most KEV additions

A CVE with several CWEs counts under each, so these rows overlap and do not sum.

| CWE | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| CWE-78 | 2,435 | 2.3% | 21 | 6.5% | 8.6 | 2.9× | 19 |
| CWE-287 | 1,481 | 1.4% | 19 | 5.9% | 12.8 | 4.3× | 12 |
| CWE-94 | 2,286 | 2.1% | 19 | 5.9% | 8.3 | 2.8× | 14 |
| CWE-22 | 3,405 | 3.2% | 18 | 5.6% | 5.3 | 1.8× | 10 |
| CWE-787 | 2,568 | 2.4% | 14 | 4.4% | 5.5 | 1.8× | 12 |
| CWE-306 | 2,122 | 2.0% | 14 | 4.4% | 6.6 | 2.2× | 13 |
| CWE-502 | 1,500 | 1.4% | 14 | 4.4% | 9.3 | 3.1× | 10 |
| CWE-416 | 3,746 | 3.5% | 13 | 4.0% | 3.5 | 1.2× | 8 |
| CWE-434 | 1,063 | 1.0% | 11 | 3.4% | 10.3 | 3.5× | 6 |
| CWE-918 | 2,400 | 2.2% | 11 | 3.4% | 4.6 | 1.5× | 7 |
| CWE-119 | 1,498 | 1.4% | 10 | 3.1% | 6.7 | 2.2× | 6 |
| CWE-89 | 4,680 | 4.3% | 9 | 2.8% | 1.9 | 0.6× | 8 |
| CWE-20 | 2,242 | 2.1% | 9 | 2.8% | 4.0 | 1.3× | 8 |
| CWE-288 | 352 | 0.3% | 9 | 2.8% | 25.6 | 8.6× | 8 |
| CWE-77 | 1,242 | 1.2% | 8 | 2.5% | 6.4 | 2.2× | 6 |

## By CVSS severity

| severity | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| CRITICAL | 11,314 | 10.5% | 147 | 45.8% | 13.0 | 4.4× | 123 |
| HIGH | 42,927 | 39.8% | 139 | 43.3% | 3.2 | 1.1× | 94 |
| MEDIUM | 39,675 | 36.8% | 34 | 10.6% | 0.9 | 0.3× | 28 |
| LOW | 7,025 | 6.5% | 1 | 0.3% | 0.1 | 0.0× | 1 |
| NONE | 69 | 0.1% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| unscored | 6,824 | 6.3% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,834 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## By CISA's SSVC exploitation value

CISA's own assessment at the time it enriched the record: `none`, `poc` (a public proof of concept) or `active`. KEV additions are `active` by construction; the useful rows are how many published CVEs carry `poc`, the supply a PoC-conditioned hazard would act on.

| exploitation | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| active | 246 | 0.2% | 321 | 100.0% | 1304.9 | 438.3× | 246 |
| poc | 21,197 | 19.7% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| none | 76,277 | 70.7% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| (not assessed) | 10,114 | 9.4% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,834 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## By SSVC automatable

| automatable | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| yes | 24,665 | 22.9% | 155 | 48.3% | 6.3 | 2.1× | 129 |
| no | 73,055 | 67.7% | 166 | 51.7% | 2.3 | 0.8× | 117 |
| (not assessed) | 10,114 | 9.4% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,834 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## By product type

`ptype` sorts each CVE by what the affected product is for: **operating system** (`os`); **productivity server** (`prodserver`); **client / user app** (`client`); **edge device** (`edge`); **infrastructure management** (`mgmt`); **other** (`other`). The rules are `PTYPE_RULES` in `cve_strata.py`, applied to the CPE families of the CVE's own vendor. CPE types 42.9% of the window's publications and every KEV addition. The rest are typed without it: 9.4% by a vendor that ships one type, 7.8% spread over the types in proportion to their vendor's typed CVEs, 32.4% from other named vendors counted as *other*, and 7.7% with no vendor following the overall mix. That is the *imputed* column; *CPE only* drops all of them and so overstates every rate, and the truth lies between the two. Intervals are exact Poisson 95% on the count of additions, with the denominator taken as known.

| product type | published, CPE only | published, imputed | share | KEV additions | share | per 1,000 (imputed) | 95% interval | per 1,000 (CPE only) | lift |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| operating system | 9,010 | 17,606 | 16.3% | 42 | 13.1% | 2.4 | 1.7–3.2 | 4.7 | 0.8× |
| productivity server | 4,274 | 7,000 | 6.5% | 65 | 20.2% | 9.3 | 7.2–11.8 | 15.2 | 3.1× |
| client / user app | 7,297 | 9,204 | 8.5% | 27 | 8.4% | 2.9 | 1.9–4.3 | 3.7 | 1.0× |
| edge device | 1,687 | 3,654 | 3.4% | 73 | 22.7% | 20.0 | 15.7–25.1 | 43.3 | 6.7× |
| infrastructure management | 1,096 | 1,736 | 1.6% | 41 | 12.8% | 23.6 | 16.9–32.0 | 37.4 | 7.9× |
| other | 22,850 | 68,634 | 63.6% | 73 | 22.7% | 1.1 | 0.8–1.3 | 3.2 | 0.4× |
| **all** | 46,214 | 107,834 | 100% | 321 | 100% | 3.0 | | | 1.0× |

### Product type × exposure: KEV additions / published, per 1,000

CPE-typed records only, on both sides, so these rates are upper bounds.

| product type | remote, no privileges, no user action | remote, other | local or physical | unscored |
|---|---:|---:|---:|---:|
| operating system | 5/1,396 = 3.6 | 10/978 = 10.2 | 27/6,636 = 4.1 | — |
| productivity server | 46/1,008 = 45.6 | 19/2,997 = 6.3 | 0/269 = 0.0 | — |
| client / user app | 2/789 = 2.5 | 18/5,042 = 3.6 | 7/1,466 = 4.8 | — |
| edge device | 54/647 = 83.5 | 13/932 = 13.9 | 6/108 = 55.6 | — |
| infrastructure management | 29/285 = 101.8 | 8/623 = 12.8 | 4/188 = 21.3 | — |
| other | 49/9,121 = 5.4 | 19/10,211 = 1.9 | 5/3,517 = 1.4 | 0/1 = 0.0 |

### Inside *other*

*Other* is a remainder, so it is split here only along fields NVD records. Of its 57,752 publications, 22,850 have CPE. The rest are unanalyzed (most are marked Deferred), and since every KEV entry has CPE they cannot be matched to the catalog: their zero is a limit of the measurement, not a rate. Counts here are whole records, without the proportional shares the table above spreads from multi-type vendors.

**By who assigned the CVE** (`channel`, from NVD's `sourceIdentifier`)

| channel | published | with CPE | KEV additions | KEV, whole catalog |
|---|---:|---:|---:|---:|
| vendor or project CNA | 15,225 | 9,987 | 32 | 196 |
| GitHub advisory | 12,107 | 6,153 | 19 | 31 |
| WordPress CNA | 10,934 | 152 | 0 | 0 |
| VulnCheck | 8,677 | 2,129 | 2 | 6 |
| VulDB | 4,670 | 1,354 | 0 | 0 |
| CISA or national CERT | 3,159 | 844 | 7 | 19 |
| MITRE | 2,189 | 1,842 | 10 | 87 |
| research or bounty CNA | 791 | 389 | 3 | 7 |

**By CPE part of the vulnerable products** (`cpe_part`)

| part | published | with CPE | KEV additions | KEV, whole catalog |
|---|---:|---:|---:|---:|
| (no CPE) | 34,902 | 0 | 0 | 0 |
| application | 20,803 | 20,803 | 62 | 250 |
| operating system or firmware | 1,771 | 1,771 | 4 | 52 |
| application and OS/firmware | 275 | 275 | 7 | 44 |
| hardware and its firmware | 1 | 1 | 0 | 0 |

**By the platform the product runs on** (`target_sw`): the 12 largest. A value here marks a plugin, package or extension; none marks a product that stands alone. A CVE listing several platforms counts under each.

| target software | published | with CPE | KEV additions | KEV, whole catalog |
|---|---:|---:|---:|---:|
| (no CPE) | 34,902 | 0 | 0 | 0 |
| (none: runs on its own) | 19,647 | 19,647 | 55 | 303 |
| `node.js` | 1,230 | 1,230 | 5 | 7 |
| `python` | 358 | 358 | 4 | 4 |
| `rust` | 261 | 261 | 0 | 0 |
| `go` | 230 | 230 | 1 | 1 |
| `wordpress` | 182 | 182 | 0 | 3 |
| `windows` | 140 | 140 | 0 | 7 |
| `joomla\!` | 122 | 122 | 5 | 5 |
| `drupal` | 115 | 115 | 0 | 0 |
| `perl` | 86 | 86 | 0 | 1 |
| `linux` | 66 | 66 | 0 | 0 |

### Share of KEV additions by year added, whole catalog

No denominators before the table's floor, so this is composition only. It shows which of the window's shares are habits of the catalog and which are one year's.

| year added | entries | operating system | productivity server | client / user app | edge device | infrastructure management | other |
|---|---:|---:|---:|---:|---:|---:|---:|
| 2021 | 311 | 23% | 15% | 16% | 14% | 11% | 22% |
| 2022 | 555 | 27% | 8% | 26% | 18% | 5% | 15% |
| 2023 | 187 | 26% | 13% | 13% | 17% | 9% | 22% |
| 2024 | 186 | 24% | 16% | 9% | 21% | 10% | 20% |
| 2025 | 245 | 23% | 18% | 7% | 22% | 10% | 20% |
| 2026 | 297 | 13% | 22% | 8% | 22% | 14% | 22% |

### What each type's KEV entries look like, whole catalog

Timing rows use entries published since the catalog opened (2021-11-03); older ones were added in bulk and their lag measures the catalog, not the attacker. Ransomware use and product names are CISA's, from `cisa_kev_2026-11-16.json`.

| | operating system | productivity server | client / user app | edge device | infrastructure management | other |
|---|---:|---:|---:|---:|---:|---:|
| KEV entries | 408 | 254 | 280 | 330 | 163 | 346 |
| known ransomware use | 20% | 32% | 12% | 19% | 25% | 17% |
| remote, no privileges, no user action | 8% | 70% | 18% | 72% | 69% | 65% |
| local or physical | 70% | 4% | 21% | 4% | 9% | 14% |
| automatable (SSVC) | 8% | 62% | 9% | 61% | 63% | 59% |
| published since the catalog opened | 201 | 163 | 84 | 182 | 105 | 165 |
| median days, publication to KEV | 0 | 22 | 1 | 5 | 13 | 27 |
| in KEV within 7 days | 63% | 34% | 82% | 58% | 42% | 31% |
| in KEV within 30 days | 70% | 54% | 89% | 71% | 60% | 52% |
| in KEV after more than a year | 6% | 6% | 1% | 8% | 9% | 13% |
| distinct products (CISA's names) | 72 | 127 | 74 | 173 | 92 | 228 |
| share held by the five most-listed products | 70% | 24% | 53% | 15% | 18% | 15% |

### Families with the most KEV additions, per type

Ranked by KEV additions in the window, then by entries in the whole catalog. A CVE counts under every family it lists, and a trailing `*` marks releases grouped into one family (`FAMILY_GROUPS`). Published counts need CPE, so a family whose recent CVEs are unanalyzed shows a rate that is too high; with fewer than about 30 published the interval says how little the rate means. *Years* is how many of the catalog's years the family was added in.

**operating system**

| family | published | KEV additions | per 1,000 | 95% interval | share of type | in catalog | years | ransomware | remote unauth. | median lag, days |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `microsoft:windows*` | 3,006 | 19 | 6 | 4–10 | 45% | 241 | 6/6 | 72 | 5% | 0 |
| `apple:ios*` | 693 | 11 | 16 | 8–28 | 26% | 94 | 6/6 | 1 | 12% | 1 |
| `apple:macos*` | 1,121 | 11 | 10 | 5–18 | 26% | 84 | 6/6 | 1 | 18% | 1 |
| `linux:linux_kernel` | 3,338 | 9 | 3 | 1–5 | 21% | 33 | 6/6 | 2 | 3% | 105.5 |
| `apple:watchos` | 316 | 8 | 25 | 11–50 | 19% | 47 | 6/6 | 1 | 11% | 1 |
| `apple:tvos` | 314 | 8 | 25 | 11–50 | 19% | 38 | 6/6 | 1 | 11% | 1 |
| `apple:visionos` | 432 | 6 | 14 | 5–30 | 14% | 17 | 3/6 | 0 | 24% | 1 |
| `google:android` | 722 | 4 | 6 | 2–14 | 10% | 21 | 6/6 | 0 | 5% | 1 |

**productivity server**

| family | published | KEV additions | per 1,000 | 95% interval | share of type | in catalog | years | ransomware | remote unauth. | median lag, days |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `microsoft:sharepoint*` | 184 | 8 | 43 | 19–86 | 12% | 20 | 5/6 | 8 | 50% | 24.5 |
| `synacor:zimbra_collaboration_suite` | 23 | 5 | 217 | 71–507 | 8% | 18 | 5/6 | 6 | 44% | 51.5 |
| `gitlab:gitlab` | 267 | 4 | 15 | 4–38 | 6% | 6 | 3/6 | 1 | 100% | 63 |
| `wordpress:wordpress` | 4 | 4 | 1000 | 272–2560 | 6% | 5 | 2/6 | 0 | 100% | 3.5 |
| `jfrog:artifactory` | 38 | 4 | 105 | 29–270 | 6% | 4 | 1/6 | 0 | 50% | 22.5 |
| `adobe:commerce*` | 73 | 3 | 41 | 8–120 | 5% | 6 | 4/6 | 0 | 83% | 39 |
| `solarwinds:web_help_desk` | 8 | 3 | 375 | 77–1096 | 5% | 5 | 2/6 | 1 | 100% | 15 |
| `smartertools:smartermail` | 6 | 3 | 500 | 103–1461 | 5% | 3 | 1/6 | 3 | 100% | 13 |

**client / user app**

| family | published | KEV additions | per 1,000 | 95% interval | share of type | in catalog | years | ransomware | remote unauth. | median lag, days |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `google:chrome` | 3,971 | 10 | 3 | 1–5 | 37% | 78 | 6/6 | 1 | 3% | 1 |
| `microsoft:office*` | 654 | 7 | 11 | 4–22 | 26% | 49 | 6/6 | 5 | 4% | 0 |
| `apple:safari` | 126 | 6 | 48 | 17–104 | 22% | 28 | 6/6 | 0 | 7% | 0 |
| `adobe:acrobat*` | 68 | 3 | 44 | 9–129 | 11% | 27 | 4/6 | 2 | 15% | 2 |
| `webkitgtk:webkitgtk` | 0 | 3 | — | — | 11% | 9 | 4/6 | 1 | 11% | 17.5 |
| `wpewebkit:wpe_webkit` | 0 | 3 | — | — | 11% | 7 | 3/6 | 1 | 0% | 17.5 |
| `microsoft:internet_explorer` | 0 | 2 | — | — | 7% | 43 | 6/6 | 8 | 16% | — |
| `microsoft:edge_chromium` | 114 | 1 | 9 | 0–49 | 4% | 9 | 5/6 | 0 | 0% | 2.5 |

**edge device**

| family | published | KEV additions | per 1,000 | 95% interval | share of type | in catalog | years | ransomware | remote unauth. | median lag, days |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `cisco:sd-wan*` | 14 | 9 | 643 | 294–1220 | 12% | 10 | 2/6 | 1 | 50% | 2.5 |
| `citrix:netscaler*` | 17 | 6 | 353 | 130–768 | 8% | 23 | 6/6 | 4 | 83% | 0 |
| `paloaltonetworks:pan-os` | 29 | 6 | 207 | 76–450 | 8% | 17 | 4/6 | 6 | 71% | 4 |
| `fortinet:fortios*` | 26 | 5 | 192 | 62–449 | 7% | 21 | 6/6 | 13 | 71% | 3.5 |
| `cisco:asa_ftd*` | 48 | 5 | 104 | 34–243 | 7% | 20 | 6/6 | 6 | 70% | 0 |
| `sonicwall:sma*` | 9 | 5 | 556 | 180–1296 | 7% | 15 | 4/6 | 7 | 60% | 1 |
| `checkpoint:gaia_quantum*` | 5 | 5 | 1000 | 325–2334 | 7% | 6 | 2/6 | 2 | 83% | 0.5 |
| `arista:velocloud_orchestrator` | 4 | 4 | 1000 | 272–2560 | 5% | 4 | 1/6 | 0 | 50% | 0.5 |

**infrastructure management**

| family | published | KEV additions | per 1,000 | 95% interval | share of type | in catalog | years | ransomware | remote unauth. | median lag, days |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ivanti:endpoint_manager_mobile` | 8 | 3 | 375 | 77–1096 | 7% | 8 | 4/6 | 2 | 62% | 3 |
| `n-able:n-central` | 3 | 3 | 1000 | 206–2922 | 7% | 5 | 2/6 | 0 | 60% | 1 |
| `papercut:ng_mf*` | 6 | 3 | 500 | 103–1461 | 7% | 5 | 3/6 | 2 | 60% | 3 |
| `simple-help:simplehelp` | 1 | 3 | 3000 | 619–8767 | 7% | 4 | 2/6 | 3 | 50% | 246.5 |
| `vmware:cloud_foundation` | 6 | 2 | 333 | 40–1204 | 5% | 19 | 5/6 | 8 | 58% | 18.5 |
| `vmware:vcenter_server` | 2 | 2 | 1000 | 121–3612 | 5% | 12 | 4/6 | 4 | 92% | 76.5 |
| `beyondtrust:remote_support` | 6 | 2 | 333 | 40–1204 | 5% | 4 | 3/6 | 1 | 75% | 4.5 |
| `connectwise:screenconnect` | 4 | 2 | 500 | 61–1806 | 5% | 4 | 3/6 | 2 | 25% | 20.5 |

**other**

| family | published | KEV additions | per 1,000 | 95% interval | share of type | in catalog | years | ransomware | remote unauth. | median lag, days |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `langflow:langflow` | 211 | 5 | 24 | 8–55 | 7% | 6 | 2/6 | 1 | 67% | 23 |
| `plex:media_server` | 9 | 4 | 444 | 121–1138 | 5% | 5 | 2/6 | 0 | 20% | 27 |
| `litellm:litellm` | 24 | 4 | 167 | 45–427 | 5% | 4 | 1/6 | 0 | 50% | 17 |
| `php:php` | 30 | 2 | 67 | 8–241 | 3% | 5 | 3/6 | 2 | 100% | 5 |
| `scadabr:scadabr` | 7 | 2 | 286 | 35–1032 | 3% | 2 | 1/6 | 0 | 0% | — |
| `adobe:coldfusion` | 106 | 1 | 9 | 0–53 | 1% | 17 | 6/6 | 4 | 94% | 79.5 |
| `oracle:weblogic_server` | 58 | 1 | 17 | 0–96 | 1% | 16 | 6/6 | 3 | 88% | 103 |
| `qualcomm:qca6391_firmware` | 80 | 1 | 12 | 0–70 | 1% | 12 | 5/6 | 0 | 0% | 0 |

## How much composition a single population rate misses

Share of KEV additions that one population-wide rate assigns to the wrong class (half the summed absolute difference between observed and expected additions). This is the baseline a stratified calibration has to beat without being fitted to it.

| partition | classes | misallocated |
|---|---:|---:|
| exposure | 4 | 26.7% |
| vendor (top 20 + 2) | 22 | 39.0% |
| vendor × exposure | 67 | 45.3% |
| severity | 6 | 38.8% |
| product type (imputed publications) | 6 | 44.3% |
