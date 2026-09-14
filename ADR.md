# Architecture Decision Records

## ADR-001: Benchmark chính là Black-box vs White-box

**Trạng thái:** Chấp nhận

**Bối cảnh:** Đề tài 4 yêu cầu so sánh định lượng fuzzing. Ba chiến lược khả dụng: black-box (thuần đột biến), greybox (coverage-guided), white-box (SMT solver).

**Quyết định:** Benchmark chính so sánh black-box và white-box. Greybox là thí nghiệm coverage bổ sung, trình bày riêng trong bảng/phần riêng biệt.

**Lý do:**
- Black-box vs white-box thể hiện rõ nhất sự khác biệt bản chất đã học ở Chương 4.5 vs 4.6: random search vs constraint solving.
- Greybox nằm giữa hai cực — dùng để minh họa cơ chế feedback loop (AFL-style) nhưng không phải trọng tâm so sánh.
- Tránh lẫn lộn khái niệm greybox với white-box (lỗi phổ biến trong tài liệu không chính thức).

---

## ADR-002: Ranh giới tri thức của Black-box Fuzzer

**Trạng thái:** Chấp nhận

**Bối cảnh:** Cần định nghĩa rõ black-box fuzzer "biết gì" và "không biết gì" để so sánh công bằng.

**Quyết định:**
- Black-box **BIẾT:** cấu trúc giao thức công khai (header layout 16 byte, quy tắc length/checksum, các giá trị type hợp lệ). Đây là thông tin có thể lấy từ tài liệu đặc tả giao thức công khai.
- Black-box **KHÔNG BIẾT:** giá trị magic `"IGW1"`, mã nguồn parser, thông tin nhánh/coverage, cặp unlock `(7421, 3390)`, hay bất kỳ mã bí mật nào. Dictionary và seed corpus không chứa `"IGW1"`.
- Benchmark unlock là bài toán **cô lập riêng**: gói có magic/header/checksum đã biết hợp lệ, chỉ randomize `unlock_a/unlock_b`. Không trộn vào kết quả crash benchmark chính.

**Lý do:**
- Mô phỏng thực tế: tester bảo mật thường biết spec giao thức nhưng không có mã nguồn nội bộ.
- Tách benchmark unlock giúp đo lường riêng rào cản "magic constant" 32-bit, minh họa trực tiếp bài toán xác suất ở Chương 4.6.
