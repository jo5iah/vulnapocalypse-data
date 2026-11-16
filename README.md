# The Data Behind the Model

The published data page for
[Exploited Vulnerabilities in a Software Ecosystem: a Measured Compartment Model](https://jo5iah.github.io/vulnapocalypse-modeling/),
served at **[jo5iah.github.io/vulnapocalypse-data](https://jo5iah.github.io/vulnapocalypse-data/)**.

It documents the sources, the measured quantities, how every model parameter is obtained, the biases in the
source data, the shape of the inflow, and the checks against the KEV catalog and the NVD corpus.

This repository holds only the built page. `index.html` is self-contained: text, figure, fonts and
libraries are inlined, so it makes no network requests. Its sources live in
[jo5iah/vulnapocalypse-modeling](https://github.com/jo5iah/vulnapocalypse-modeling): the text in
`VulnData.md`, the figure and data acquisition in `VulnData.ipynb`. To update it:

```bash
# in vulnapocalypse-modeling
python build_html.py VulnData
cp VulnData.html ../vulnapocalypse-data/index.html
```
