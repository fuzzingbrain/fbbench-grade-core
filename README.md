# fbbench-grade-core

The grading engine for [FuzzingBrain-Bench](https://github.com/fuzzingbrain/FuzzingBrain-Bench) — a single-shot, MCP-free judge.

It is published **for transparency**: this is the exact code that decides, for one candidate input against one challenge, which capability rungs fire (reach / crash / differential / class / site) and whether the target bug was reproduced. Researchers can read and reproduce the grading logic here.

## What it is

A small Go module (one binary). Given an assembled oracle bundle and one candidate input:

```
grade-core -oracle-dir /path/to/<challenge-bundle> -input /path/to/candidate.bin [-rounds N]
```

it prints the verdict as JSON on stdout.

```
go build -o grade-core .
```

## No answers live here

This repo contains only the grading **logic**. It contains **no per-challenge answers**: the answer bundle (`expected.yaml`, the ground-truth binaries) is supplied at run time via `-oracle-dir` and lives only in the private grading backend. Nothing in this source reveals any bug's location, PoC, or expected class/site.

## Single source of truth

Both the public benchmark (for transparency) and the grading backend consume this module. Grading is done **remotely** by the backend — end users running the benchmark never build or run this themselves.
