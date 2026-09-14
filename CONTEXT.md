# CONTEXT — Glossary

Thuật ngữ dùng xuyên suốt dự án BTL Nhóm 11.

| Thuật ngữ | Định nghĩa |
|---|---|
| **GatewayMessage** | Gói tin nhị phân tuân theo giao thức SecureGate IoT Gateway: header 16 byte little-endian + payload + checksum 4 byte. |
| **PacketParser** | Chương trình C (`gateway_parser.c`) nhận đường dẫn file chứa một `GatewayMessage`, kiểm tra tính hợp lệ và xử lý nội dung. |
| **Magic** | 4 byte đầu header, phải là `"IGW1"` (`0x49 0x47 0x57 0x31`). Đóng vai trò rào cản (guard) đầu tiên mà fuzzer cần vượt qua. |
| **Checksum** | 4 byte cuối gói (sau payload), bằng tổng tất cả byte của header và payload modulo 2³². Parser reject gói có checksum không khớp. |
| **CrashOracle** | Cơ chế phát hiện crash: target được build với `-fsanitize=address,undefined`; crash khi ASan phát hiện vi phạm bộ nhớ (return code ≠ 0 + stderr chứa `"AddressSanitizer"`). |
| **Corpus** | Tập hợp các file gói nhị phân dùng làm hạt giống (seed) cho fuzzer. Greybox mở rộng corpus khi tìm input tạo coverage mới. |
| **Trial** | Một lần chạy fuzzer độc lập với seed cố định và ngân sách tối đa 5.000 input. Mỗi thí nghiệm gồm 30 trial (seed 0..29). |
| **UniqueCrash** | Crash được khử trùng lặp (deduplicate) bằng ASan stack signature — hai crash có cùng stack trace tính là một. |
| **Black-box Fuzzer** | Fuzzer không biết mã nguồn, không đọc coverage. Biết cấu trúc giao thức công khai (header layout, length/checksum rules) nhưng **không** biết giá trị magic `"IGW1"` hay bất kỳ mã bí mật nào. |
| **Greybox Fuzzer** | Fuzzer dùng phản hồi coverage (gcov statement coverage) để ưu tiên giữ lại input mở thêm dòng lệnh mới. Không dùng SMT solver. Mô phỏng đơn giản ý tưởng AFL. |
| **White-box Fuzzer** | Fuzzer dùng SMT solver (Z3) để giải ngược path predicate, sinh trực tiếp gói hợp lệ vượt qua mọi rào cản (magic, version, checksum, device_id_len = 24) và kích hoạt crash CWE-121. |
| **Unlock** | Nhánh xử lý `type=0x02` trong parser, yêu cầu `unlock_a=7421` và `unlock_b=3390`. Dùng làm bài toán cô lập rào cản 32-bit code trong benchmark phụ. |
