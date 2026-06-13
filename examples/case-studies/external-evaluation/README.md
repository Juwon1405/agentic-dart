# External-evaluation cases (public datasets)

Three **real, third-party public datasets** used to validate the agent on data
the author did not create. Each is a multi-GB forensic image under its own
licence, so the full evidence is **not committed** to this repo — it is fetched
on demand. If you `ls` here and see mostly `README.md` + `truth.json`, that is
by design.

| Case | Dataset | Bundled here | Full evidence |
|---|---|---|---|
| case-01 | NIST CFReDS Hacking Case (Greg Schardt / "Mr. Evil") | small `evidence-snippet/` taster + `SCHARDT.LOG` | `--download` |
| case-02 | Ali Hadi DFIR Challenge #1 (web server) | spec only | `--download` |
| case-03 | Digital Corpora M57-Patents (subject **Jo**) | spec only | `--download` |

## Why case-01 has a snippet but case-02 / case-03 don't

NIST CFReDS "Mr. Evil" has small, freely-redistributable artifacts (the
`SCHARDT.LOG`, the published answer key `TestAnswers.txt`, `Hacking_Case.html`),
so `case-01/evidence-snippet/` ships them as an illustrative taster — you can
see the shape of the case without the full NTFS image. Ali Hadi and M57 are
larger / less snippet-friendly, so only the scenario spec is bundled.

For all three, the full image is downloaded on demand (size + licensing keep it
out of git):

```bash
python3 run_eval.py --case external-evaluation/case-01 --download
```

Dataset registry, checksums, and fetch commands:
`../../scripts/benchmark/datasets.py` and
`python3 -m scripts.benchmark.download --help`. The full case table is in
[`../README.md`](../README.md).
