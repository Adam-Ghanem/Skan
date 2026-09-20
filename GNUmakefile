# Repository-level additions layered over the existing build without rewriting it.
include Makefile

.PHONY: corpus-test corpus-roundtrip corpus-verify corpus-external-verify corpus-performance

corpus-test:
	python3 -m unittest discover -s tests/corpus -p 'test_*.py' -v

corpus-roundtrip:
	python3 -m tools.corpus.migrate_first_party --root . --check

corpus-verify: corpus-test corpus-roundtrip
	python3 -m tools.corpus.validate --root .

corpus-external-verify: corpus-verify
	python3 -m tools.corpus.cli stats --root .

corpus-performance:
	python3 -m tools.corpus.performance --root . --max-load-seconds 20 --max-peak-rss-mib 1024

# Extend the existing C++ test target with the corpus contract.
test: corpus-test
