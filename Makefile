# BTL Nhom 11 — SecureGate Binary Parser Fuzzing
# Makefile

CC       = gcc
CFLAGS   = -g -Wall -Wextra -fsanitize=address,undefined --coverage
SRC_DIR  = src
SRC      = $(SRC_DIR)/gateway_parser.c
BIN_VULN = $(SRC_DIR)/parser_vuln
BIN_FIXED= $(SRC_DIR)/parser_fixed

PYTHON   = python3
PYTEST   = $(PYTHON) -m pytest

.PHONY: all vuln fixed test cppcheck clean \
        fuzz-blackbox fuzz-whitebox fuzz-greybox benchmark charts

all: vuln fixed

vuln: $(SRC)
	$(CC) $(CFLAGS) -o $(BIN_VULN) $(SRC)

fixed: $(SRC)
	$(CC) $(CFLAGS) -DFIXED_VERSION -o $(BIN_FIXED) $(SRC)

test: vuln fixed
	$(PYTEST) tests/ -v --tb=short

cppcheck:
	cppcheck --enable=all --inconclusive --std=c11 \
	         --suppress=missingIncludeSystem $(SRC)

fuzz-blackbox: vuln
	$(PYTHON) fuzzers/blackbox_fuzzer.py

fuzz-whitebox: vuln
	$(PYTHON) fuzzers/whitebox_fuzzer.py

fuzz-greybox: vuln
	$(PYTHON) fuzzers/greybox_fuzzer.py

benchmark: vuln
	$(PYTHON) scripts/run_benchmark.py

charts:
	$(PYTHON) scripts/generate_charts.py

clean:
	rm -f $(BIN_VULN) $(BIN_FIXED)
	rm -f $(SRC_DIR)/*.gcda $(SRC_DIR)/*.gcno $(SRC_DIR)/*.gcov
	rm -f crashes/*.txt crashes/*.bin
	rm -f data/raw/*.json data/raw/*.csv
	rm -f report/figures/*.png
