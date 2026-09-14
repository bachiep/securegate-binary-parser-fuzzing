# BTL Nhóm 11 — SecureGate Binary Parser Fuzzing

[![Validate project](https://github.com/bachiep/securegate-binary-parser-fuzzing/actions/workflows/ci.yml/badge.svg)](https://github.com/bachiep/securegate-binary-parser-fuzzing/actions/workflows/ci.yml)

**Đề tài 4: Kiểm thử mờ (Fuzzing)**
Học phần CSE703093 — An toàn phần mềm

## Yêu cầu

- GCC với hỗ trợ ASan/UBSan và gcov
- Python 3.10+
- Z3 solver (`pip install z3-solver`)
- pytest (`pip install pytest`)
- matplotlib (`pip install matplotlib`)
- cppcheck (tuỳ chọn)

## Quick Start

```bash
# 1. Build target (vulnerable + fixed)
make vuln fixed

# 2. Chạy test suite (30 tests)
make test

# 3. Chạy static analysis
make cppcheck

# 4. Demo từng fuzzer
make fuzz-blackbox    # Black-box: ~5000 inputs, xác suất crash cực thấp
make fuzz-whitebox    # White-box: Z3 giải, tìm crash ngay
make fuzz-greybox     # Greybox: gcov feedback + byte sweep coverage-guided

# 5. Benchmark đầy đủ (30 trials × 3 fuzzer)
make benchmark
# ⚠️ Greybox chậm do gcov per-input. Có checkpoint/resume.
# Greybox thuc hien toi da 30 x 5000 input va co the mat hang chuc phut.

# 6. Tổng hợp kết quả
python3 scripts/aggregate_results.py

# 7. Tạo biểu đồ
python3 scripts/generate_charts.py
```

## Cấu trúc thư mục

```
BTL/
├── CONTEXT.md          # Glossary thuật ngữ
├── ADR.md              # Quyết định kiến trúc
├── README.md           # File này
├── Makefile            # Build & automation
├── src/
│   └── gateway_parser.c   # Target C parser (vuln + fixed)
├── fuzzers/
│   ├── packet_builder.py  # Module xây gói dùng chung
│   ├── blackbox_fuzzer.py # Fuzzer hộp đen
│   ├── whitebox_fuzzer.py # Fuzzer hộp trắng (Z3)
│   ├── greybox_fuzzer.py  # Fuzzer greybox (gcov)
│   └── unlock_benchmark.py # Benchmark mã unlock
├── tests/
│   ├── test_parser.py     # 18 tests cho parser
│   └── test_fuzzers.py    # 9 tests cho fuzzers
├── scripts/
│   ├── run_benchmark.py   # Chạy 30 trials × 3 fuzzer
│   ├── aggregate_results.py # Tổng hợp → bảng Markdown
│   └── generate_charts.py # Matplotlib biểu đồ 300 DPI
├── seed_corpus/           # Binary seed files
├── crashes/               # Crash artifacts (auto)
├── data/raw/              # Raw benchmark JSON
└── report/
    ├── BAO_CAO_BTL.md     # Báo cáo Markdown
    └── figures/           # Biểu đồ
```

## Giao thức SecureGate

Header 16 byte (little-endian):

| Offset | Trường | Giá trị |
|:---:|---|---|
| 0–3 | magic | `"IGW1"` |
| 4 | version | `1` |
| 5 | type | `0x01`/`0x02` |
| 6 | device_id_len | `24` trong crash profile benchmark |
| 7 | flags | `0` |
| 8–9 | payload_len | `≥ device_id_len` |
| 10–11 | unlock_a | `7421` (Unlock) |
| 12–13 | unlock_b | `3390` (Unlock) |
| 14–15 | reserved | `0` |

Checksum: `sum(header + payload) mod 2³²`

## Lỗi CWE-121 (cài chủ đích)

`device_id_len` cho phép tới 32 nhưng buffer chỉ 16 byte → `memcpy` tràn stack. Benchmark chính cố định framing công khai và ID ASCII 24 byte để cả ba fuzzer truy cùng crash profile; black-box chỉ đoán magic ngẫu nhiên, không bị cấm nhân tạo. Bản fixed reject `device_id_len > 16`.

## Tiếp tục benchmark greybox bị gián đoạn

```bash
# Greybox có checkpoint — chạy lại lệnh benchmark sẽ tiếp từ trial cuối
make benchmark
```

## Tái tạo từ đầu

```bash
make clean
make vuln fixed
make benchmark    # Chạy lại toàn bộ 30 trials
python3 scripts/aggregate_results.py
python3 scripts/generate_charts.py
```
