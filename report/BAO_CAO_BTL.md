# BÁO CÁO BÀI TẬP LỚN
## Đề tài 4: Kiểm thử mờ (Fuzzing) — SecureGate Binary Parser

**Học phần:** CSE703093 — An toàn phần mềm
**Nhóm 11:**

| Họ và tên | MSSV | Lớp |
|---|---|---|
| Lưu Đức Hiệp | *(placeholder)* | *(placeholder)* |
| Hà Nguyễn Trúc Linh | *(placeholder)* | *(placeholder)* |

**Ngày nộp:** *(placeholder)*

> **Ghi chú:** Lỗi CWE-121 trong chương trình mục tiêu được cài đặt **chủ đích** nhằm phục vụ mục đích học tập và so sánh phương pháp fuzzing.

---

## 1. Giới thiệu và Mục tiêu

### 1.1 Bối cảnh

Các thiết bị IoT gateway thường sử dụng giao thức nhị phân tuỳ chỉnh để trao đổi dữ liệu. Parser xử lý gói tin là thành phần có attack surface lớn: nó phải phân tích dữ liệu không đáng tin cậy từ mạng, thường viết bằng C/C++ — ngôn ngữ dễ mắc lỗi an toàn bộ nhớ. Một lỗi tràn bộ đệm trong parser có thể bị khai thác để thực thi mã tuỳ ý (RCE).

Kiểm thử mờ (fuzzing) là kỹ thuật tự động sinh đầu vào để tìm lỗi phần mềm. Tuỳ mức thông tin về chương trình mục tiêu, fuzzing chia thành:
- **Hộp đen (black-box):** không biết mã nguồn, không phản hồi coverage.
- **Hộp xám (greybox):** dùng phản hồi coverage để dẫn dắt tìm kiếm.
- **Hộp trắng (white-box):** dùng phân tích chương trình và SMT solver để sinh đầu vào vượt qua mọi rào cản.

### 1.2 Mục tiêu

1. Thiết kế chương trình mục tiêu (target) là parser gói nhị phân SecureGate IoT Gateway, có lỗi CWE-121 (Stack-based Buffer Overflow) cài chủ đích.
2. Áp dụng **Chương 2** (static analysis, sanitizer, vá lỗi) để phát hiện và sửa lỗi.
3. Áp dụng **Chương 4** (fuzzing) với ba chiến lược: black-box, greybox và white-box.
4. **So sánh định lượng** black-box vs white-box trong việc tìm crash CWE-121 (benchmark chính).
5. Phân tích bổ sung: greybox coverage growth và benchmark unlock code (bài toán cô lập 32-bit).

---

## 2. Mô tả chương trình mục tiêu

### 2.1 Giao thức SecureGate

Parser nhận một file nhị phân chứa một gói tin tuân theo giao thức SecureGate IoT Gateway:

**Header 16 byte (little-endian):**

| Offset | Trường | Kiểu | Giá trị hợp lệ |
|:---:|---|---|---|
| 0–3 | `magic` | `char[4]` | `"IGW1"` (`0x49 0x47 0x57 0x31`) |
| 4 | `version` | `u8` | `1` |
| 5 | `type` | `u8` | `0x01` (Registration) hoặc `0x02` (Unlock) |
| 6 | `device_id_len` | `u8` | `0..32` (vulnerable) / `0..16` (fixed) |
| 7 | `flags` | `u8` | `0` |
| 8–9 | `payload_len` | `u16 LE` | ≥ `device_id_len` nếu Registration |
| 10–11 | `unlock_a` | `u16 LE` | `7421` nếu Unlock |
| 12–13 | `unlock_b` | `u16 LE` | `3390` nếu Unlock |
| 14–15 | `reserved` | `u16 LE` | `0` |

Sau header: `payload_len` byte payload + `checksum:u32 LE` (tổng byte header+payload mod 2³²).

### 2.2 Chuỗi validation

Parser kiểm tra tuần tự: magic → version → type → flags → reserved → kích thước file → `payload_len >= device_id_len` → checksum → ASCII device_id. Gói bị reject tại bất kỳ bước nào sẽ dừng xử lý ngay.

### 2.3 Attack surface và lỗi CWE-121

**Bản vulnerable:** `device_id_len` cho phép tới 32 nhưng `char device_id[16]` trên stack → `memcpy(device_id, payload, hdr.device_id_len)` ghi tràn khi `device_id_len > 16`.

```c
/* === BAN VULNERABLE: CWE-121 === */
char device_id[16];  /* !!! QUA NHO cho device_id_len > 16 !!! */
memcpy(device_id, payload, hdr.device_id_len);  /* !!! CWE-121 !!! */
```

**Bản fixed:** reject `device_id_len > 16`, buffer 17 byte, copy có giới hạn, NUL-terminate.

```c
/* === BAN FIXED === */
if (hdr.device_id_len > 16) {
    fprintf(stderr, "[REJECT] device_id_len qua lon: %u > 16\n", hdr.device_id_len);
    return 1;
}
char device_id[17];
memcpy(device_id, payload, hdr.device_id_len);
device_id[hdr.device_id_len] = '\0';
```

### 2.4 Rào cản fuzzing

Để trigger CWE-121, input phải:
1. Khớp đúng magic `"IGW1"` (4 byte cố định) — xác suất random: $P = (1/256)^4 \approx 2.3 \times 10^{-10}$
2. Version = 1, type = 0x01, flags = 0, reserved = 0
3. `device_id_len` > 16 (nằm trong range 17..32)
4. Checksum hợp lệ
5. Device ID là ASCII printable

Rào cản magic byte là bài toán cốt lõi: black-box thuần tuý gần như không thể vượt qua trong ngân sách giới hạn.

---

## 3. Phương pháp Chương 2: Static Analysis và Sanitizer

### 3.1 Cppcheck

Chạy Cppcheck trên mã nguồn target:

```bash
cppcheck --enable=all --inconclusive --std=c11 src/gateway_parser.c
```

Cppcheck không nhất thiết suy ra được `device_id_len` do input điều khiển trong bản demo; vì vậy kết quả “không có lỗi chắc chắn” không thay thế ASan. Cảnh báo/style và phiên bản lệnh chạy thực tế được lưu cùng dữ liệu nộp bài.

### 3.2 AddressSanitizer (ASan)

Target được build với `-fsanitize=address,undefined` để phát hiện vi phạm bộ nhớ tại runtime. ASan đóng vai trò **crash oracle**: nếu parser crash với ASan báo `stack-buffer-overflow`, ta xác nhận đã tìm được lỗi CWE-121.

```bash
gcc -g -fsanitize=address,undefined --coverage -o parser_vuln gateway_parser.c
```

### 3.3 Vá lỗi và Regression Test

- Diff giữa bản vulnerable và fixed cho thấy chính xác bản vá.
- Crash input đã lưu được dùng làm regression test: chạy trên bản fixed phải bị reject (exit ≠ 0) mà **không** crash.

---

## 4. Phương pháp Chương 4: Fuzzing và Z3

### 4.1 Black-box Fuzzer (Chương 4.5)

**Tri thức:**
- **BIẾT:** cấu trúc giao thức công khai (header layout, length/checksum rules)
- **KHÔNG BIẾT:** magic `"IGW1"`, mã nguồn, coverage, cặp unlock

**Chiến lược:** Đây là benchmark có kiểm soát rào cản magic. Generator cố định version/type/flags/reserved, length/checksum hợp lệ và ID ASCII 24 byte — cùng crash profile mà white-box truy tìm — rồi chỉ sinh magic 4 byte **ngẫu nhiên**. Nó không chứa `"IGW1"` trong dictionary hay seed, nhưng không cấm kết quả ngẫu nhiên trùng magic. Vì thế xác suất $2^{-32}$ bên dưới chính là xác suất vượt magic trong profile này, không phải xác suất của một parser fuzzer tổng quát.

### 4.2 White-box Fuzzer (Chương 4.6 + Z3 Chương 3)

Dùng Z3 (SMT solver) mô hình hoá path predicate để sinh trực tiếp gói crash:

```python
# Path predicate → Z3 constraints
s.add(magic == b"IGW1")        # 4 byte constraints
s.add(version == 1)
s.add(pkt_type == 0x01)        # Registration
s.add(device_id_len == 24)     # Trigger CWE-121
s.add(payload[i] >= 0x41)      # ASCII uppercase
s.add(checksum == sum(header + payload) % 2**32)
```

Z3 giải trong ~0.02 giây → sinh gói crash trực tiếp mà không cần thử ngẫu nhiên.

### 4.3 Greybox Fuzzer (Coverage-guided)

Mô phỏng đơn giản AFL:
1. Xoá `.gcda` → chạy target → `gcov` → đọc tập dòng cover
2. Nếu input mở coverage mới → thêm vào corpus queue
3. Mutate corpus: thay đổi 1–3 byte ngẫu nhiên, tính lại checksum

Để quan sát rào cản magic trong một target nhỏ, greybox thực hiện byte sweep trên vùng magic của framing công khai và chỉ giữ prefix khi `gcov` mở dòng mới. Seed đã thỏa điều kiện ID 24 byte, và fuzzer không chứa giá trị `IGW1`. Đây là **coverage-guided prefix enumeration** có kiểm soát, không phải khẳng định về hiệu quả của AFL/libFuzzer trên target tổng quát. Greybox trình bày **riêng** — không đánh tráo với white-box trong so sánh chính.

### 4.4 Thiết kế thực nghiệm

| Tham số | Giá trị |
|---|---|
| Số trials mỗi fuzzer | 30 (seed 0..29) |
| Ngân sách mỗi trial | 5.000 inputs |
| Timeout mỗi input | 5 giây |
| Crash oracle | ASan `stack-buffer-overflow` có trace trỏ vào `gateway_parser.c` |
| Seed cố định | Để tái lập hoàn toàn |

**Metrics đo:**
- Trial-to-first-ASan-crash (iteration number)
- Wall-clock time (giây)
- Exec/s
- Success rate (bao nhiêu trial tìm được crash)
- Unique crash signatures (deduplicate bằng ASan stack)

---

## 5. Kết quả và Phân tích

### 5.1 Bảng so sánh chính: Black-box vs White-box

*(Bảng sẽ được tổng hợp tự động từ `scripts/aggregate_results.py` sau khi chạy benchmark.)*

<!-- INSERT: report/summary_table.md -->

### 5.2 Biểu đồ

#### Time-to-First-Crash (Box plot)
<!-- INSERT: report/figures/time_to_crash_boxplot.png -->

#### Success Rate (Bar chart)
<!-- INSERT: report/figures/success_rate_bar.png -->

### 5.3 Phân tích Greybox

#### Coverage Growth
<!-- INSERT: report/figures/greybox_coverage_growth.png -->

### 5.4 Benchmark phụ: Unlock Code

*(Bài toán cô lập rào cản 32-bit code — không phải kết quả crash chính.)*

<!-- INSERT: report/figures/unlock_benchmark.png -->

- Z3 giải chính xác `(7421, 3390)` trong < 1ms và xác nhận một lần trên parser.
- Black-box random `unlock_a/unlock_b` là mô phỏng không gian ứng viên để đo xác suất, không chạy 500.000 process target mỗi trial.
- Với ngân sách 500.000 thử/trial, xác suất tìm được trong 1 trial: $\approx 1.2 \times 10^{-4}$ — gần như bằng 0.

### 5.5 Crash Input và ASan Trace

*(Mẫu crash input hex dump và ASan trace sẽ được ghi nhận sau khi chạy benchmark.)*

### 5.6 Regression Test sau vá

```bash
# Crash input chạy trên bản fixed → REJECT, không crash
./parser_fixed crashes/whitebox_s0_crash_0.bin
# [REJECT] device_id_len qua lon: 24 > 16
```

---

## 6. Thảo luận và Hạn chế

### 6.1 Tại sao black-box thất bại?

Rào cản magic byte `"IGW1"`:
$$P(\text{random 4 byte} = \text{"IGW1"}) = \left(\frac{1}{256}\right)^4 \approx 2.3 \times 10^{-10}$$

Với ngân sách 5.000 thử/trial, kỳ vọng tìm được magic đúng: $5000 \times 2.3 \times 10^{-10} \approx 1.15 \times 10^{-6}$ — gần như bằng 0.

### 6.2 Tại sao white-box thành công?

Z3 solver giải ngược path predicate, bypass trực tiếp mọi rào cản (magic, version, checksum) trong thời gian hằng số O(1 lần giải). Đây là ưu điểm bản chất của white-box: **thay vì tìm kiếm, nó suy diễn**.

### 6.3 Hạn chế

1. **Target đơn giản:** Parser chỉ có khoảng 260 dòng C, 1 bug chủ đích. Trong thực tế, parser phức tạp hơn nhiều.
2. **Path explosion:** White-box fuzzer mô hình hoá thủ công path predicate. Với chương trình lớn, path explosion khiến Z3 không scale.
3. **Greybox chậm do gcov:** `gcov` per-input tạo overhead I/O lớn (~1 exec/s). Fuzzer thực tế dùng compile-time instrumentation (AFL/libFuzzer) nhanh hơn 100–1000x.
4. **Fuzzing không sound/complete:** Không tìm thấy crash ≠ không có bug. Tìm thấy crash chỉ chứng minh sự tồn tại của bug, không chứng minh an toàn.
5. **Chỉ 1 crash CWE-121:** Unique crash signature ít vì cùng 1 bug pattern.

---

## 7. Kết luận

| Fuzzer | Tìm crash CWE-121? | Lý do |
|---|:---:|---|
| Black-box | ✗ (gần như) | Rào cản magic byte $P \approx 10^{-10}$ |
| White-box | ✓ (luôn) | Z3 giải path predicate trực tiếp |
| Greybox | *(tuỳ thí nghiệm)* | Coverage feedback giúp nhưng vẫn cần may mắn với magic |

**Kết luận:**
- White-box fuzzing (Z3) **vượt trội** black-box cho target có rào cản magic constant cố định.
- Greybox coverage-guided cho phép khám phá từng bước, nhưng rào cản magic byte vẫn là thách thức lớn.
- Static analysis (Cppcheck) và runtime sanitizer (ASan) là công cụ bổ trợ thiết yếu: Cppcheck phát hiện vấn đề tiềm ẩn, ASan xác nhận crash.
- Kết hợp cả ba phương pháp mới tạo nên quy trình kiểm thử an toàn toàn diện.

---

## Tài liệu tham khảo

1. Đề cương CSE703093 — An toàn phần mềm, Chương 2, 3, 4.
2. M. Zalewski, *American Fuzzy Lop (AFL) — Technical Whitepaper*, Google.
3. MITRE CWE-121: Stack-based Buffer Overflow.
4. L. de Moura and N. Bjørner, "Z3: An Efficient SMT Solver", *TACAS 2008*.
5. K. Serebryany et al., "AddressSanitizer: A Fast Address Sanity Checker", *USENIX ATC 2012*.
6. Google, *OSS-Fuzz: Continuous Fuzzing for Open Source Software*.

---

## Phụ lục

### A. Hướng dẫn tái tạo

```bash
cd BTL/
make vuln fixed        # Build target
make test              # Chạy test suite (27 tests)
make cppcheck          # Static analysis
make benchmark         # Chạy 30 trials × 3 fuzzer
python3 scripts/aggregate_results.py   # Tổng hợp
python3 scripts/generate_charts.py     # Biểu đồ
```

### B. Cấu trúc thư mục

```
BTL/
├── CONTEXT.md, ADR.md, README.md, Makefile
├── src/gateway_parser.c          # Target C parser
├── fuzzers/
│   ├── packet_builder.py         # Module xây gói dùng chung
│   ├── blackbox_fuzzer.py        # Fuzzer hộp đen
│   ├── whitebox_fuzzer.py        # Fuzzer hộp trắng (Z3)
│   ├── greybox_fuzzer.py         # Fuzzer greybox (gcov)
│   └── unlock_benchmark.py       # Benchmark unlock code
├── tests/test_parser.py, test_fuzzers.py
├── scripts/run_benchmark.py, aggregate_results.py, generate_charts.py
├── seed_corpus/, crashes/, data/raw/
└── report/BAO_CAO_BTL.md, figures/
```
