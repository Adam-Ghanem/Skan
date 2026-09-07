# Repository-level additions layered over the existing build without rewriting it.
include Makefile

.PHONY: corpus-test corpus-verify

corpus-test:
	python3 -m unittest discover -s tests/corpus -p 'test_*.py' -v

corpus-verify: corpus-test
	python3 -m tools.corpus.validate --root .

# Extend the existing C++ test target with the corpus contract.
test: corpus-test
