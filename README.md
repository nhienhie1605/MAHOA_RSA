# HỆ THỐNG BỎ PHIẾU ĐIỆN TỬ MINH BẠCH DỰA TRÊN THUẬT TOÁN MÃ HÓA RSA HAI CẶP KHÓA KẾT HỢP CHỮ KÝ SỐ
## Giới thiệu
Dự án ứng dụng thuật toán mã hóa RSA hai cặp khóa kết hợp chữ ký số để xây dựng hệ thống bỏ phiếu điện tử đảm bảo an toàn, bảo mật và minh bạch.

Giải pháp này giúp mã hóa phiếu bầu, xác thực danh tính người bỏ phiếu và bảo vệ tính toàn vẹn dữ liệu trong toàn bộ quy trình bầu cử

### ⚙️ Cơ chế hoạt động
1. Người bỏ phiếu sinh một cặp khóa RSA (Public/Private Key 1).
2. Ban kiểm phiếu sinh cặp khóa riêng (Public/Private Key 2).
3. Người bỏ phiếu:
- Ký số phiếu bầu bằng Private Key 1.
- Mã hóa phiếu đã ký bằng Public Key 2.
4. Ban kiểm phiếu:
- Giải mã phiếu bằng Private Key 2.
- Xác thực chữ ký bằng Public Key 1.

### 👩‍💻 Thực hiện bởi: Đoàn Lê Yến Nhi và các thành viên trong nhóm
#### Đoàn Lê Yến Nhi
- Email: doannhi1605@gmail.com
- Github: https://github.com/nhienhie1605
