# CVE stratification — 365 days to 2026-11-16

Built by `cve_strata.py report` from `data/cve_strata.csv.gz` (last synced with NVD 2026-11-16T18:00:32 UTC, table floor 2025-11-16). **Published**: 107,720 CVEs with an NVD publication date in (2025-11-16, 2026-11-16]. **KEV additions**: 321 CVEs CISA added in the same window, whatever their publication date; 246 of them were also published in it. *Per 1,000 published* divides the two, the stratified analogue of the model's conversion; *lift* is a class's share of KEV additions over its share of publications.

## Coverage of each field

| field | published in window | KEV additions |
|---|---:|---:|
| vendor from NVD CPE applicability | 42.8% | 100.0% |
| vendor from the assigner's `affected` block | 49.5% | 0.0% |
| any vendor | 92.3% | 100.0% |
| CVSS vector (exposure class) | 93.6% | 100.0% |
| … scored by NVD itself | 7.8% | 23.1% |
| weakness type (CWE) | 90.4% | 99.4% |
| SSVC decision points (CISA) | 90.3% | 100.0% |

## By exposure class

| exposure (CVSS) | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| remote, no privileges, no user action | 33,324 | 30.9% | 185 | 57.6% | 5.6 | 1.9× | 152 |
| remote, other | 47,171 | 43.8% | 87 | 27.1% | 1.8 | 0.6× | 60 |
| local or physical | 20,363 | 18.9% | 49 | 15.3% | 2.4 | 0.8× | 34 |
| unscored | 6,862 | 6.4% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,720 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## By vendor: the 20 with most KEV additions, and the rest

Vendors are chosen by exploitation, not volume. Rates for vendors whose CVEs are often unanalyzed are overstated to the extent their publications sit in *(no vendor recorded)*.

| vendor | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| microsoft | 5,665 | 5.3% | 42 | 13.1% | 7.4 | 2.5× | 29 |
| cisco | 406 | 0.4% | 22 | 6.9% | 54.2 | 18.2× | 20 |
| apple | 1,260 | 1.2% | 12 | 3.7% | 9.5 | 3.2× | 7 |
| google | 4,935 | 4.6% | 12 | 3.7% | 2.4 | 0.8× | 12 |
| fortinet | 256 | 0.2% | 11 | 3.4% | 43.0 | 14.4× | 11 |
| linux | 9,322 | 8.7% | 8 | 2.5% | 0.9 | 0.3× | 4 |
| ivanti | 65 | 0.1% | 8 | 2.5% | 123.1 | 41.3× | 8 |
| adobe | 1,269 | 1.2% | 7 | 2.2% | 5.5 | 1.9× | 5 |
| oracle | 4,154 | 3.9% | 6 | 1.9% | 1.4 | 0.5× | 3 |
| sonicwall | 53 | 0.0% | 6 | 1.9% | 113.2 | 38.0× | 6 |
| citrix | 45 | 0.0% | 6 | 1.9% | 133.3 | 44.7× | 6 |
| synacor | 25 | 0.0% | 5 | 1.6% | 200.0 | 67.1× | 3 |
| vmware | 195 | 0.2% | 5 | 1.6% | 25.6 | 8.6× | 3 |
| langflow | 218 | 0.2% | 5 | 1.6% | 22.9 | 7.7× | 5 |
| paloaltonetworks | 112 | 0.1% | 5 | 1.6% | 44.6 | 15.0× | 5 |
| checkpoint | 23 | 0.0% | 5 | 1.6% | 217.4 | 73.0× | 5 |
| gitlab | 271 | 0.3% | 4 | 1.2% | 14.8 | 5.0× | 2 |
| solarwinds | 48 | 0.0% | 4 | 1.2% | 83.3 | 28.0× | 3 |
| arista | 9 | 0.0% | 4 | 1.2% | 444.4 | 149.1× | 4 |
| jfrog | 45 | 0.0% | 4 | 1.2% | 88.9 | 29.8× | 4 |
| (other vendors) | 71,084 | 66.0% | 140 | 43.6% | 2.0 | 0.7× | 101 |
| (no vendor recorded) | 8,260 | 7.7% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,720 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## Vendor × exposure: KEV additions / published, per 1,000

| vendor | remote, no privileges, no user action | remote, other | local or physical | unscored |
|---|---:|---:|---:|---:|
| microsoft | 10/775 = 12.9 | 16/1,679 = 9.5 | 16/3,211 = 5.0 | — |
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
| (other vendors) | 95/26,065 = 3.6 | 37/35,298 = 1.0 | 8/9,589 = 0.8 | 0/132 = 0.0 |
| (no vendor recorded) | 0/2,588 = 0.0 | 0/2,250 = 0.0 | 0/436 = 0.0 | 0/2,986 = 0.0 |

## By weakness type: the 15 with most KEV additions

A CVE with several CWEs counts under each, so these rows overlap and do not sum.

| CWE | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| CWE-78 | 2,432 | 2.3% | 21 | 6.5% | 8.6 | 2.9× | 19 |
| CWE-287 | 1,479 | 1.4% | 19 | 5.9% | 12.8 | 4.3× | 12 |
| CWE-94 | 2,285 | 2.1% | 19 | 5.9% | 8.3 | 2.8× | 14 |
| CWE-22 | 3,399 | 3.2% | 18 | 5.6% | 5.3 | 1.8× | 10 |
| CWE-787 | 2,565 | 2.4% | 14 | 4.4% | 5.5 | 1.8× | 12 |
| CWE-306 | 2,120 | 2.0% | 14 | 4.4% | 6.6 | 2.2× | 13 |
| CWE-502 | 1,499 | 1.4% | 14 | 4.4% | 9.3 | 3.1× | 10 |
| CWE-416 | 3,744 | 3.5% | 13 | 4.0% | 3.5 | 1.2× | 8 |
| CWE-434 | 1,063 | 1.0% | 11 | 3.4% | 10.3 | 3.5× | 6 |
| CWE-918 | 2,395 | 2.2% | 11 | 3.4% | 4.6 | 1.5× | 7 |
| CWE-119 | 1,497 | 1.4% | 10 | 3.1% | 6.7 | 2.2× | 6 |
| CWE-89 | 4,677 | 4.3% | 9 | 2.8% | 1.9 | 0.6× | 8 |
| CWE-20 | 2,241 | 2.1% | 9 | 2.8% | 4.0 | 1.3× | 8 |
| CWE-288 | 352 | 0.3% | 9 | 2.8% | 25.6 | 8.6× | 8 |
| CWE-77 | 1,242 | 1.2% | 8 | 2.5% | 6.4 | 2.2× | 6 |

## By CVSS severity

| severity | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| CRITICAL | 11,306 | 10.5% | 147 | 45.8% | 13.0 | 4.4× | 123 |
| HIGH | 42,871 | 39.8% | 139 | 43.3% | 3.2 | 1.1× | 94 |
| MEDIUM | 39,595 | 36.8% | 34 | 10.6% | 0.9 | 0.3× | 28 |
| LOW | 7,017 | 6.5% | 1 | 0.3% | 0.1 | 0.0× | 1 |
| NONE | 69 | 0.1% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| unscored | 6,862 | 6.4% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,720 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## By CISA's SSVC exploitation value

CISA's own assessment at the time it enriched the record: `none`, `poc` (a public proof of concept) or `active`. KEV additions are `active` by construction; the useful rows are how many published CVEs carry `poc`, the supply a PoC-conditioned hazard would act on.

| exploitation | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| active | 246 | 0.2% | 321 | 100.0% | 1304.9 | 437.9× | 246 |
| poc | 21,139 | 19.6% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| none | 75,866 | 70.4% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| (not assessed) | 10,469 | 9.7% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,720 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## By SSVC automatable

| automatable | published | share | KEV additions | share | per 1,000 published | lift | published in window and in KEV |
|---|---:|---:|---:|---:|---:|---:|---:|
| yes | 24,582 | 22.8% | 155 | 48.3% | 6.3 | 2.1× | 129 |
| no | 72,669 | 67.5% | 166 | 51.7% | 2.3 | 0.8× | 117 |
| (not assessed) | 10,469 | 9.7% | 0 | 0.0% | 0.0 | 0.0× | 0 |
| **all** | 107,720 | 100% | 321 | 100% | 3.0 | 1.0× | 246 |

## By product type

`ptype` sorts each CVE by what the affected product is for: **operating system** (`os`); **productivity server** (`prodserver`); **client / user app** (`client`); **edge device** (`edge`); **other** (`other`). The rules are `PTYPE_RULES` in `cve_strata.py`, applied to the CPE families of the CVE's own vendor. CPE types 42.8% of the window's publications and every KEV addition. The rest are typed without it: 9.2% by a vendor that ships one type, 7.9% spread over the types in proportion to their vendor's typed CVEs, 32.5% from other named vendors counted as *other*, and 7.7% with no vendor following the overall mix. That is the *imputed* column; *CPE only* drops all of them and so overstates every rate, and the truth lies between the two. Intervals are exact Poisson 95% on the count of additions, with the denominator taken as known.

| product type | published, CPE only | published, imputed | share | KEV additions | share | per 1,000 (imputed) | 95% interval | per 1,000 (CPE only) | lift |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| operating system | 9,011 | 17,776 | 16.5% | 45 | 14.0% | 2.5 | 1.8–3.4 | 5.0 | 0.8× |
| productivity server | 4,258 | 7,027 | 6.5% | 64 | 19.9% | 9.1 | 7.0–11.6 | 15.0 | 3.1× |
| client / user app | 7,242 | 9,137 | 8.5% | 21 | 6.5% | 2.3 | 1.4–3.5 | 2.9 | 0.8× |
| edge device | 1,649 | 3,613 | 3.4% | 74 | 23.1% | 20.5 | 16.1–25.7 | 44.9 | 6.9× |
| other | 23,930 | 70,166 | 65.1% | 117 | 36.4% | 1.7 | 1.4–2.0 | 4.9 | 0.6× |
| **all** | 46,090 | 107,720 | 100% | 321 | 100% | 3.0 | | | 1.0× |

### Product type × exposure: KEV additions / published, per 1,000

CPE-typed records only, on both sides, so these rates are upper bounds.

| product type | remote, no privileges, no user action | remote, other | local or physical | unscored |
|---|---:|---:|---:|---:|
| operating system | 5/1,386 = 3.6 | 12/982 = 12.2 | 28/6,643 = 4.2 | — |
| productivity server | 45/1,007 = 44.7 | 19/2,982 = 6.4 | 0/269 = 0.0 | — |
| client / user app | 1/788 = 1.3 | 15/4,992 = 3.0 | 5/1,462 = 3.4 | — |
| edge device | 54/629 = 85.9 | 13/913 = 14.2 | 7/107 = 65.4 | — |
| other | 80/9,419 = 8.5 | 28/10,813 = 2.6 | 9/3,697 = 2.4 | 0/1 = 0.0 |

### Share of KEV additions by year added, whole catalog

No denominators before the table's floor, so this is composition only. It shows which of the window's shares are habits of the catalog and which are one year's.

| year added | entries | operating system | productivity server | client / user app | edge device | other |
|---|---:|---:|---:|---:|---:|---:|
| 2021 | 311 | 23% | 14% | 15% | 14% | 34% |
| 2022 | 555 | 26% | 8% | 25% | 18% | 23% |
| 2023 | 187 | 28% | 13% | 9% | 17% | 33% |
| 2024 | 186 | 24% | 16% | 9% | 19% | 33% |
| 2025 | 245 | 22% | 16% | 5% | 21% | 35% |
| 2026 | 297 | 13% | 22% | 7% | 22% | 36% |

### What each type's KEV entries look like, whole catalog

Timing rows use entries published since the catalog opened (2021-11-03); older ones were added in bulk and their lag measures the catalog, not the attacker. Ransomware use and product names are CISA's, from `cisa_kev_2026-11-16.json`.

| | operating system | productivity server | client / user app | edge device | other |
|---|---:|---:|---:|---:|---:|
| KEV entries | 403 | 246 | 254 | 327 | 551 |
| known ransomware use | 18% | 33% | 12% | 19% | 21% |
| remote, no privileges, no user action | 7% | 70% | 17% | 72% | 65% |
| local or physical | 69% | 4% | 23% | 5% | 13% |
| automatable (SSVC) | 7% | 62% | 9% | 61% | 58% |
| published since the catalog opened | 207 | 158 | 65 | 179 | 291 |
| median days, publication to KEV | 0 | 25 | 1 | 5 | 18 |
| in KEV within 7 days | 64% | 33% | 83% | 58% | 37% |
| in KEV within 30 days | 71% | 53% | 91% | 72% | 56% |
| in KEV after more than a year | 6% | 6% | 0% | 7% | 11% |
| distinct products (CISA's names) | 65 | 120 | 68 | 173 | 345 |
| share held by the five most-listed products | 72% | 25% | 56% | 15% | 10% |

### Families with the most KEV additions, per type

Ranked by KEV additions in the window, then by entries in the whole catalog. A CVE counts under every family it lists, and a trailing `*` marks releases grouped into one family (`FAMILY_GROUPS`). Published counts need CPE, so a family whose recent CVEs are unanalyzed shows a rate that is too high; with fewer than about 30 published the interval says how little the rate means. *Years* is how many of the catalog's years the family was added in.

**operating system**

| family | published | KEV additions | per 1,000 | 95% interval | share of type | in catalog | years | ransomware | remote unauth. | median lag, days |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `microsoft:windows*` | 3,006 | 19 | 6 | 4–10 | 42% | 241 | 6/6 | 72 | 5% | 0 |
| `apple:ios*` | 693 | 11 | 16 | 8–28 | 24% | 94 | 6/6 | 1 | 12% | 1 |
| `apple:macos*` | 1,121 | 11 | 10 | 5–18 | 24% | 84 | 6/6 | 1 | 18% | 1 |
| `linux:linux_kernel` | 3,338 | 9 | 3 | 1–5 | 20% | 33 | 6/6 | 2 | 3% | 105.5 |
| `apple:watchos` | 316 | 8 | 25 | 11–50 | 18% | 47 | 6/6 | 1 | 11% | 1 |
| `apple:tvos` | 314 | 8 | 25 | 11–50 | 18% | 38 | 6/6 | 1 | 11% | 1 |
| `apple:visionos` | 432 | 6 | 14 | 5–30 | 13% | 17 | 3/6 | 0 | 24% | 1 |
| `google:android` | 722 | 4 | 6 | 2–14 | 9% | 21 | 6/6 | 0 | 5% | 1 |

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
| `google:chrome` | 3,968 | 10 | 3 | 1–5 | 48% | 78 | 6/6 | 1 | 3% | 1 |
| `microsoft:office*` | 605 | 7 | 12 | 5–24 | 33% | 49 | 6/6 | 5 | 4% | 0 |
| `apple:safari` | 126 | 6 | 48 | 17–104 | 29% | 28 | 6/6 | 0 | 7% | 0 |
| `adobe:acrobat*` | 68 | 3 | 44 | 9–129 | 14% | 27 | 4/6 | 2 | 15% | 2 |
| `webkitgtk:webkitgtk` | 0 | 3 | — | — | 14% | 9 | 4/6 | 1 | 11% | 17.5 |
| `wpewebkit:wpe_webkit` | 0 | 3 | — | — | 14% | 7 | 3/6 | 1 | 0% | 17.5 |
| `microsoft:internet_explorer` | 0 | 2 | — | — | 10% | 43 | 6/6 | 8 | 16% | — |
| `microsoft:edge_chromium` | 114 | 1 | 9 | 0–49 | 5% | 9 | 5/6 | 0 | 0% | 2.5 |

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

**other**

| family | published | KEV additions | per 1,000 | 95% interval | share of type | in catalog | years | ransomware | remote unauth. | median lag, days |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `langflow:langflow` | 211 | 5 | 24 | 8–55 | 4% | 6 | 2/6 | 1 | 67% | 23 |
| `plex:media_server` | 9 | 4 | 444 | 121–1138 | 3% | 5 | 2/6 | 0 | 20% | 27 |
| `litellm:litellm` | 24 | 4 | 167 | 45–427 | 3% | 4 | 1/6 | 0 | 50% | 17 |
| `ivanti:endpoint_manager_mobile` | 8 | 3 | 375 | 77–1096 | 3% | 8 | 4/6 | 2 | 62% | 3 |
| `n-able:n-central` | 3 | 3 | 1000 | 206–2922 | 3% | 5 | 2/6 | 0 | 60% | 1 |
| `papercut:ng_mf*` | 6 | 3 | 500 | 103–1461 | 3% | 5 | 3/6 | 2 | 60% | 3 |
| `simple-help:simplehelp` | 1 | 3 | 3000 | 619–8767 | 3% | 4 | 2/6 | 3 | 50% | 246.5 |
| `vmware:cloud_foundation` | 6 | 2 | 333 | 40–1204 | 2% | 19 | 5/6 | 8 | 58% | 18.5 |

## How much composition a single population rate misses

Share of KEV additions that one population-wide rate assigns to the wrong class (half the summed absolute difference between observed and expected additions). This is the baseline a stratified calibration has to beat without being fitted to it.

| partition | classes | misallocated |
|---|---:|---:|
| exposure | 4 | 26.7% |
| vendor (top 20 + 2) | 22 | 39.0% |
| vendor × exposure | 67 | 45.3% |
| severity | 6 | 38.8% |
| product type (imputed publications) | 5 | 33.1% |
