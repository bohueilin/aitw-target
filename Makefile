# Operational targets. All offline and deterministic.
# The stock target substrate (read-only sibling clone) is needed by the test/selftest targets so the
# defense layer can run over the published target tools. Override AITW_SRC to point elsewhere; it is
# harmless on the path for the other targets.
AITW_SRC ?= $(abspath $(CURDIR)/../aitw-target/src)
export PYTHONPATH := src:$(AITW_SRC)
PYTHON ?= $(shell if [ -x .venv/bin/python ]; then printf '.venv/bin/python'; else printf 'python3'; fi)
PIP ?= $(PYTHON) -m pip

.PHONY: test selftest reset bootstrap lint guard secret-scan deps-guard sast dep-audit \
        label-scan security-all clean

test:                ## run the test suite (substrate-dependent cases skip if the target is not on the path)
	$(PYTHON) -m pytest -q

selftest:            ## run the provider self-acceptance check against the stock target substrate
	$(PYTHON) scripts/acceptance_selfcheck.py

reset clean:         ## remove run artifacts, workspaces, and caches (contained to the repo root)
	$(PYTHON) -c "from agent_runtime.safety.reset import safe_reset; print('removed:', safe_reset())"

bootstrap:           ## lock-constrained install into the active env + guards
	$(PIP) install --upgrade pip
	$(PIP) install -c requirements.lock -e ".[dev]"
	$(PYTHON) -m agent_runtime.safety.dependency_guard
	$(PYTHON) -m agent_runtime.safety.secret_guard
	@echo "bootstrap OK"

label-scan:          ## fail if the tree carries any internal/condition labels
	$(PYTHON) scripts/label_scan.py

lint:                ## ruff lint (warn-and-skip if ruff is not installed)
	@if $(PYTHON) -m ruff --version >/dev/null 2>&1; then \
		$(PYTHON) -m ruff check src/ scripts/ tests/; \
	else \
		echo "ruff not installed — skipping lint (install with: pip install -e '.[dev]')"; \
	fi

guard secret-scan:   ## repo credential/secret scan
	$(PYTHON) -m agent_runtime.safety.secret_guard

deps-guard:          ## dependency-confusion verification (vendored packages resolve locally)
	$(PYTHON) -m agent_runtime.safety.dependency_guard

sast:                ## static security scan (bandit; warn-and-skip if bandit is not installed)
	@if command -v bandit >/dev/null 2>&1; then \
		bandit -q -r src/ -c pyproject.toml; \
	else \
		echo "bandit not installed — skipping SAST (install with: pip install -e '.[security]')"; \
	fi

dep-audit:           ## dependency vulnerability audit (warn-and-skip if pip-audit is not installed)
	@if command -v pip-audit >/dev/null 2>&1; then \
		pip-audit -r requirements.lock --progress-spinner off; \
	else \
		echo "pip-audit not installed — skipping dependency audit (install with: pip install -e '.[security]')"; \
	fi

security-all: lint sast secret-scan dep-audit deps-guard label-scan ## all checks
	@echo "ALL CHECKS PASSED"
