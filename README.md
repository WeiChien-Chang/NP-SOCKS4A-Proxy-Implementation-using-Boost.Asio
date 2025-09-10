# Network Programming: SOCKS4A_Proxy_Implementation_using_Boost.Asio

> 以 **Boost.Asio 非同步網路** 為核心，實作 **SOCKS4/4A CONNECT / BIND**、**Allow-list 防火牆（支援熱更新）**，並提供 **CGI 即時串流主控台**（多目標並列、XSS 安全輸出）。

## 目錄
- [專案概觀](#專案概觀)
- [功能總覽](#功能總覽)
- [SOCKS4/4A](#SOCKS4/4A)

## 專案概觀

本專案包含兩部分：

- **SOCKS 伺服器**（`socks_server.cpp`）  
  - 支援 **SOCKS4/4A** 協定（CONNECT / BIND）。  
  - **Allow-list 防火牆**（萬用字元 `*`），每次請求即讀取設定檔，**不需重啟即可生效**。  
  - 非同步網路 I/O、每連線 `fork()` 分工、`SIGCHLD` 非同步回收。

- **CGI Proxy / 多主機主控台**（`console.cpp` → 部署為 `pj5.cgi`）  
  - 充當 **SOCKS4A Client**，可同時連線至多台遠端主機（最多 5 欄）。  
  - 以 `<script>` 片段 + `flush()` **即時串流輸出**，並做 **HTML escape 與安全換行**，避免 XSS 與頁面破版。  
  - 以 shell `% ` prompt 偵測就緒，**節流指令送出**（先送 `who\n` 做 sanity check）。

---

## 功能總覽

- **SOCKS4/4A CONNECT**（代理端可做 DNS 解析 / 4A）
- **SOCKS4/4A BIND**（完整兩段 `90` 回覆、再進入雙向 relay）
- **CGI 即時主控台**（多目標並列、逐段 `<script>` 注入 + flush）
- **HTML 安全輸出**（`html_escape()`；`\n` → `&NewLine;`）
- **Allow-list 防火牆**（`permit c|b <ip-pattern>`；熱更新）
- **穩定性**（`fork()`、`SIGCHLD`、`io_context.notify_fork()` 與非同步 I/O）

## SOCKS4/4A
> 參考：
> - [SOCKS Protocol Version 4](https://www.openssh.com/txt/socks4.protocol)
> - [SOCKS Protocol Version 4A](https://www.openssh.com/txt/socks4a.protocol)

### 什麼是 SOCKS4 與 4A？
- **SOCKS4** 是一種位於應用層與傳輸層之間的 **TCP 代理協定**，對應用協定本身（HTTP、FTP、Telnet…）**不關心內容**，主要負責幫用戶端在代理端「代為建立」到目標伺服器的 TCP 連線，之後只做雙向轉送（relay）。
- **SOCKS4A** 是 SOCKS4 的**簡單擴充**：當用戶端 **無法自行做 DNS 解析** 時，可把 **網域名稱** 交給 SOCKS 伺服器，由代理端解析後再連線。

---

### 封包結構（Request / Reply 摘要）

**Client → Server（CONNECT 或 BIND 請求）**
