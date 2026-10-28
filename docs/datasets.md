# Public labeled datasets

SentinelMesh does not download or redistribute public datasets. Download CSV flow exports only from the dataset owner, keep them outside this repository, and use the benchmark CLI with a bounded row limit. Do not import PCAP payloads.

## CIC-IDS2017

Official source: [Canadian Institute for Cybersecurity dataset page](https://www.unb.ca/cic/datasets/ids-2017.html). The page describes labeled CSV flows and PCAPs and requests citation of the dataset paper. The page does not present a standard open-source license grant; verify the current access and use terms with the provider before use, especially for commercial purposes. This loader expects CICFlowMeter CSV columns such as `Source IP`, `Destination IP`, `Protocol`, `Timestamp`, `Flow Duration`, forward/backward packet counts, forward bytes, and `Label`. Timestamp strings are naive; pass the capture timezone explicitly. `--timezone UTC` is an assumption, not provider metadata.

## UNSW-NB15

Official source: [UNSW-NB15 dataset page](https://research.unsw.edu.au/projects/unsw-nb15-dataset). The page grants free academic research use, asks users to cite the listed publications, and says commercial use requires agreement with the authors. Confirm current terms and required citations before use. The loader expects CSV columns including `srcip`, `sport`, `dstip`, `dsport`, `proto`, `dur`, `spkts`, `dpkts`, `sbytes`, `stime`, and `label` or `attack_cat`.

## Reproducible evaluation

```bash
sentinelmesh benchmark --dataset cic-ids2017 --input path/to/flows.csv --timezone UTC
sentinelmesh benchmark --dataset unsw-nb15 --input path/to/flows.csv
```

The default reads up to 20,000 rows and the maximum is 100,000. The benchmark sorts by event timestamp and keeps the first 80% for training/earlier context and the last 20% for evaluation. `rules` is the default model; `--model isolation-forest` requires the optional `ml` extra and fits only on the earlier partition. Precision, recall, F1, average precision (stepwise PR area), and false alerts per observed day are returned. No public-dataset result is currently claimed because no dataset file is included or downloaded by this project. A result must identify the dataset/version, selected rows, timestamp assumptions, and model configuration; do not combine these metrics with synthetic fixture counts.
