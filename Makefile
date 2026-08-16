.PHONY: release-check docs-check docs-build ci-remote ci-local ci

ci-remote:
	bash scripts/ci_remote.sh

ci-local:
	bash scripts/ci_local.sh

ci: ci-local

release-check:
	python3 -B -m unittest \
		scripts.tests.test_prepare_release \
		scripts.tests.test_auto_release \
		scripts.tests.test_bump_doc_versions \
		scripts.tests.test_publish_retry \
		scripts.tests.test_release_workflows \
		scripts.tests.test_release_notes \
		scripts.tests.test_release_integrity_receipt

# Keep generated README evidence, operator contracts, and mdBook links coherent.
docs-check:
	python3 -B scripts/gates/docs_truth.py
	python3 -B scripts/gates/action_docs_contract.py
	python3 -B scripts/gates/workflow_docs_boundaries.py
	python3 -B -m unittest scripts.tests.test_action_docs_contract scripts.tests.test_workflow_docs_boundaries
	python3 -B scripts/star_history.py --check
	python3 -B -m unittest scripts.tests.test_star_history
	$(MAKE) -C benchmarks readme-matrix-check
	$(MAKE) -C benchmarks readme-scaling-check
	cd docs && mdbook test && mdbook build
	python3 -B scripts/gates/docs_links.py docs/book --site-prefix /keyhog/

docs-build: docs-check
	python3 -B scripts/docs_site.py docs/book
