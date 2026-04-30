# Aegis Phase 1 Analysis

This package is intentionally deterministic and side-effect free.

The PR diff parser and classifiers should only inspect local diff content and
return structured classification data. Phase 1 must not call databases,
external APIs, Semgrep, CodeQL, or LLMs from this package.
