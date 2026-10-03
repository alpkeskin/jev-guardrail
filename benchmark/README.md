# Benchmark

Measures the guardrail end to end against TypeSafe's Jev: latency and
throughput under a fixed load, and detection accuracy on a labeled corpus
of up to 100,000 public samples.

```bash
uv run benchmark/datasets/prepare.py --total 100000    # build the corpus (once)
JEV_API_KEY=<typesafe key> benchmark/run.sh            # run and report
```

The report is written to `benchmark/results/<run>/report.md`, with raw data
next to it. `data/` and `results/` are git-ignored.

## How it works

```
samples.jsonl ──► loadgen ──► guardrail container ──► TypeSafe /v1/systemone
  (labeled)       fixed RPS    X-Client-ID: benchmark
                     │
                     ▼
               results.jsonl ──► report ──► report.md, summary.json
               (all 8 scores)    ThresholdEngine + any policy
```

1. **Corpus** (`datasets/prepare.py`). Downloads public datasets from the
   Hugging Face Hub, gives every sample exactly one label, removes
   duplicates and texts over 8,000 characters, balances the mix and
   shuffles it with a fixed seed. `data/manifest.json` records the counts.
2. **Run** (`run.sh`). Builds the image and starts the guardrail with the
   shipped policies plus `policies/benchmark.yaml`. That policy enables
   every category as `review` with a near-zero threshold, so each response
   carries all eight scores and nothing is blocked.
3. **Load** (`cmd/loadgen`). Open-loop: request *i* is due at
   `start + i/RPS` whatever happened before, with at most `CONCURRENCY` in
   flight. Latency is recorded twice. *Service* time runs from send to
   response. *End-to-end* time runs from the scheduled send time, so client
   queueing under saturation is not hidden (coordinated omission).
4. **Report** (`cmd/report`). Recomputes every judgment offline with the
   production `ThresholdEngine` and the policy given by `POLICY` (default
   `policies/eval-all.yaml`: every category blocks at the default
   thresholds). Changing thresholds only needs the report rerun:

   ```bash
   go run ./benchmark/cmd/report -results benchmark/results/<run>/results.jsonl -policy policies/default.yaml
   ```

5. **Tuning** (`cmd/tune`). Picks thresholds for a policy's blocking
   categories from the **calibration split** only: 30% of samples,
   assigned deterministically by ID hash. Every category gets the same
   budget of benign false positives. The largest budget whose combined
   false positive rate stays within `-target-fpr` wins. Report tuned
   policies on the **test split** (`-split test`), which tuning never sees:

   ```bash
   go run ./benchmark/cmd/tune -results benchmark/results/<run>/results.jsonl -policy policies/default.yaml -target-fpr 0.03
   go run ./benchmark/cmd/report -results benchmark/results/<run>/results.jsonl -policy policies/default.yaml -split test
   ```

The benchmark policy asks Jev all eight questions on every request. The
shipped default policy asks six, so production requests are slightly
smaller than benchmark requests.

## Labels

| Label | Counts as detected when one of these matches | Sources |
|---|---|---|
| `prompt_attack` | `PROMPT_INJECTION`, `JAILBREAK`, `SYSTEM_PROMPT_LEAK` | xTRam1/safe-guard-prompt-injection, deepset/prompt-injections, jackhhao/jailbreak-classification, Lakera/gandalf_ignore_instructions, TrustAIRLab/in-the-wild-jailbreak-prompts, yanismiraoui/prompt_injections, jayavibhav/prompt-injection |
| `harmful_request` | `MALICIOUS_INSTRUCTION`, `UNSAFE_CONTENT` | LLM-LAT/harmful-dataset, mlabonne/harmful_behaviors, declare-lab/CategoricalHarmfulQA, JailbreakBench/JBB-Behaviors |
| `unsafe_response` | `MALICIOUS_INSTRUCTION`, `UNSAFE_CONTENT` | PKU-Alignment/BeaverTails (unsafe replies in clearly harmful categories) |
| `pii` | `SENSITIVE_DATA` | ai4privacy/pii-masking-300k (rows with an email, phone, ID, passport, licence, street address or birth date; six languages) |
| `secret` | `SECRET_EXFILTRATION`, `SENSITIVE_DATA` | synthetic: random credentials in config and chat snippets |
| `malicious_url` | `MALICIOUS_URL` | pirocheto/phishing-url (phishing) |
| `benign` | nothing (must pass) | hard negatives from the attack datasets above, BeaverTails safe replies, legitimate URLs, secret snippets with placeholders or env lookups, Dolly (instructions and Wikipedia passages), Alpaca |

Each sample is in exactly one bucket. A sample is a **true positive** when
it should be blocked under the evaluated policy and is. **Attribution** is
reported separately: the share of detected samples whose primary reason is
one of the label's categories.

### Known limitations

* **Label noise.** Public datasets disagree on what an injection is. Some
  benign "regular" prompts from the jailbreak communities are borderline,
  and BeaverTails labels the question and answer as a pair while only the
  answer is screened here. Per-source tables show where disagreement
  comes from. Read the misclassified examples before drawing conclusions.
* **Excluded data.** SPML positives are excluded because they are labeled
  against a per-row system prompt the guardrail never sees. Their benign
  prompts are kept.
* **Synthetic data.** No public dataset labels leaked credentials in prose,
  so secrets are synthetic. Positives and negatives share templates, and
  only the value differs.
* **Malicious URLs.** Jev has no URL reputation data. The URL label measures
  what can be judged from the URL text alone.
* **Licences.** Some sources are non-commercial (BeaverTails, Alpaca:
  CC BY-NC 4.0). The corpus is built locally for evaluation and is not
  redistributed.

## Settings

All `run.sh` settings are environment variables:

| Variable | Default | |
|---|---|---|
| `JEV_API_KEY` | required | TypeSafe key. It is passed to the container by name, never as a process argument. |
| `RUN` | timestamp | Results directory name. Reusing a name resumes the run: samples that already succeeded are skipped. |
| `RPS` | `40` | Offered load. TypeSafe allows 80 requests/s and 100k tokens/s per account. |
| `CONCURRENCY` | `64` | Maximum requests in flight. Also used as the guardrail's `JEV_MAX_CONCURRENCY`. |
| `LIMIT` | `0` (all) | Send only the first N samples. The corpus is shuffled, so any prefix is a random mix. |
| `JEV_MODEL` | `jev-1.13.0` | Model under test. It is pinned so that runs stay comparable. |
| `POLICY` | `benchmark/policies/eval-all.yaml` | Policy the report evaluates. |
| `JEV_URL` | TypeSafe | For example `http://host.docker.internal:8000` to dry-run the tooling against `make mockjev`. |

**Cost.** A full run sends about 100,000 requests and roughly 75M input
tokens: about 38M characters of content plus about 650 tokens of questions
per request. At 40 requests/s it takes about 42 minutes. Start with
`LIMIT=1000`.

## Output

| File | Content |
|---|---|
| `report.md` | Summary, latency percentiles (by length and content type), failures, confusion matrix, accuracy by label, source, content type and language with Wilson 95% intervals, false-positive causes, ROC AUC and threshold sweep per label, misclassified examples |
| `summary.json` | The same figures, machine-readable |
| `results.jsonl` | One line per request: timings, status, all scores |
| `meta.json` | Run settings, git commit, corpus hash |
| `metrics.txt` | Guardrail Prometheus metrics at the end of the run |
| `guardrail.log` | Guardrail warnings and errors (content is never logged) |
