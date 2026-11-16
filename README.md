# The Data Behind the Model

Data, acquisition and data-side analyses for
[Exploited Vulnerabilities in a Software Ecosystem: a Measured Compartment Model](https://jo5iah.github.io/vulnapocalypse-modeling/).
The data page is published at **[jo5iah.github.io/vulnapocalypse-data](https://jo5iah.github.io/vulnapocalypse-data/)**.
It documents the sources, the measured quantities, how every model parameter is obtained, the biases in the
source data, the shape of the inflow, and the checks against the KEV catalog and the NVD corpus.

The model lives in [jo5iah/vulnapocalypse-modeling](https://github.com/jo5iah/vulnapocalypse-modeling),
which includes this repository as the submodule `vulnapocalypse-data` and reads `data/` from it. Snapshot:
**2026-11-16**.

## Contents

| File | Description |
|---|---|
| `index.html` | The data page, self-contained: text, figure, fonts and libraries are inlined, so it makes no network requests. Served by GitHub Pages. |
| `VulnData.md` | The data page's text, the only written account of the data. |
| `VulnData.ipynb` | Data acquisition. Queries NVD for the CVE corpus, publication rates and the 2008-to-present history (yearly, monthly and daily), CISA KEV for observed exploitation, and MITRE for disclosure timestamps. Writes every input the model reads, and draws the inflow figure on the data page. Responses are cached; the snapshot date (`AS_OF`) is the single control at the top. |
| `data/` | Cached API responses, one set per snapshot, and the derived inputs: `derived_params.json` (measured quantities), `global_history.json` (per-year publication rates), `trend_series_<snapshot>.json` and `trend_daily_<snapshot>.json` (monthly and daily series), `sharepoint_union.json` (the de-duplicated SharePoint CVE set). Delete a file to refetch it. |
| `product_ranks.py` | Top products by CVE count and by observed exploitation, both from NVD's CPE applicability data, so the two rankings share one taxonomy. Writes `data/product_ranks_<snapshot>.json` and the report `product_ranks_<snapshot>.md`; `--report-only` rebuilds the report from the saved JSON. |
| `cve_strata.py` | Per-CVE stratification table (`data/cve_strata.csv.gz`): vendor, product families, CVSS exposure fields, severity, CWE, SSVC decision points and KEV date for every CVE of the trailing year. `build` sweeps NVD, `update` refetches only modified records, `report` rebuilds the tables offline. |
| `cve_stratification_<snapshot>.md` | KEV additions per 1,000 CVEs published, by exposure class, vendor, weakness type, severity and SSVC value. Input to step 2 of the model's plan. |
| `impact_ledger.py`, `impact/` | The exploitation-impact ledger: published counts of exposed instances, compromised hosts, victim organizations, attack volume and downtime per KEV entry, assembled from the research batches under `impact/`. |
| `impact_ledger_<snapshot>.md` | The ledger so far. Partial (96 of 2026's 297 KEV additions); input to step 3 of the model's plan. |
| `build_html.py`, `vendor/` | Build the page: `python build_html.py VulnData index`. `vendor/` holds KaTeX with its fonts and markdown-it. |
| `environment.yml`, `environment.lock.yml` | Conda environment, the same one the model uses. |

The files above moved here from the model repository with their git history, so each snapshot keeps the
commit that introduced it.

## Reproducing

```bash
conda env create -f environment.yml && conda activate aysu
jupyter lab VulnData.ipynb             # refresh the data; bump AS_OF for a new snapshot
python build_html.py VulnData index    # rebuild index.html
```

After a new snapshot, commit here, then update the submodule in vulnapocalypse-modeling
(`git submodule update --remote vulnapocalypse-data`) and rerun the model notebook.
