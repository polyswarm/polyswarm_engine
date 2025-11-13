.DEFAULT_GOAL := help

EXAMPLE_SOURCES := $(wildcard examples/*/engine.py)
SOURCES := setup.py $(wildcard polyswarm_engine/*.py) $(EXAMPLE_SOURCES)

# Binaries
PYTHON := python3
PIP := pip3
FLAKE8 := flake8
PYTEST := $(PYTHON) -m pytest
ISORT := isort
MYPY := $(PYTHON) -m mypy
YAPF := yapf --exclude '$(TESTS_DIR)/*'

export WINEDEBUG := -all

define PRINT_HELP_PYSCRIPT
import re, sys
print("%s" % '$(ENGINE_NAME)')
print("-" * 60)
for path in sys.argv[1:]:
	with open(path, 'rt') as f:
		for line in f:
			match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
			if match:
				target, help = match.groups()
				print("%-25s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

.PHONY: help
help:
	@$(PYTHON) -c "$$PRINT_HELP_PYSCRIPT" $(MAKEFILE_LIST)

.PHONY: check
check:  ## Run all tests, type checks & lint rules
	$(PIP) install tox
	$(PYTHON) -m tox

.PHONY: lint
lint: $(SOURCES) ## Lint sources
	$(MYPY)
	$(MYPY) examples/alibaba/engine.py
	$(MYPY) examples/jiangmin/engine.py
	$(MYPY) examples/nanoav/engine.py
	$(MYPY) examples/secureage/engine.py
	$(YAPF) --diff $?
	$(ISORT) --check --diff $?
	$(FLAKE8) $?

.PHONY: format
format: $(SOURCES) ## Format sources
	$(YAPF) --in-place $?
	$(ISORT) $?

.PHONY: clean
clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts

.PHONY: clean-build
clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . \( -path ./env -o -path ./venv -o -path ./.env -o -path ./.venv \) -prune -o -name '*.egg-info' -exec rm -fr {} +
	find . \( -path ./env -o -path ./venv -o -path ./.env -o -path ./.venv \) -prune -o -name '*.egg' -exec rm -f {} +

.PHONY: clean-pyc
clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

.PHONY: clean-test
clean-test: ## remove test and coverage artifacts
	rm -f .coverage
	rm -fr htmlcov
	rm -fr .pytest_cache
	rm -fr .tox
	find . -name '.mypy_cache' -exec rm -fr {} +
