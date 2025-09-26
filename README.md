# Network Programming: SOCKS4A_Proxy_Implementation_using_Boost.Asio

[Note: SOCKS4/4A, CGI, Firewall(PDF)](./note/note.pdf)
> 以 **Boost.Asio 非同步網路** 為核心，實作 **SOCKS4/4A CONNECT / BIND**、**Allow-list 防火牆（支援熱更新）**，並實作CGI 提供Web server能夠執行外部程式的標準介面。

---

## 專案簡介
- **非阻塞 I/O 與事件驅動**：兩個部份都以 Boost.Asio 的 async API 撰寫，沒有阻塞呼叫。  
- **協議與互通性**：完整走過 **SOCKS4/4A** 的 CONNECT 與 BIND 流程（含 **BIND 的兩階段 90 回覆**），能與一般工具/客戶端互通。  
- **安全與健壯性**：前端 **HTML escape** 防止 XSS、後端 **Firewall 規則**，並具備基本錯誤處理與日誌。  

---

## 檔案結構
- `console.cpp` — **Web 端多主機互動 Console（CGI 程式）**  
  - 解析 `QUERY_STRING`（支援 `h0/p0/f0` 形式與 `sh/sp` SOCKS 參數）。  
  - 透過 SOCKS4a 與多個遠端 shell 互動，**即時輸出到瀏覽器**（逐段 `<script>` append）。  
  - 針對輸出做 **HTML escape** 與換行處理，避免破版與 XSS。  

- `socks_server.cpp` — **SOCKS4/4A 代理伺服器**  
  - 支援 **CONNECT / BIND**，完成 **雙向資料轉送**。  
  - **BIND** 採兩階段成功回覆（第一次回報 listen 埠、第二次遠端接上後回報對端資訊）。  
  - 內建 **Firewall**（簡易白名單；支援萬用字元 `*` 比對），預設拒絕。  
  - `fork`-per-connection、`SIGCHLD` 非阻塞回收，確保Parent Process穩定。

---

## 兩份程式的角色與功能

### 1) `console.cpp` — Browser 互動的「遠端操作台」
我把它部署在支援 CGI 的 Web 伺服器下，使用者只要在網址列帶上參數（例如 `h0/p0/f0`、`sh/sp`），程式就會：
- 建立多個非同步連線到 SOCKS 代理，再由代理連到目標主機（最多五台）。  
- 從 `./test_case/<file>` 逐行餵指令給遠端 shell。  
- 以 **即時輸出** 的方式把回應顯示在瀏覽器的表格中（每台主機一格）。  

### 2) `socks_server.cpp` — 支援 CONNECT / BIND 的 SOCKS4/4A 代理
這個元件負責協議面與資料轉送：
- **CONNECT**：解析請求（含 4A 的 DOMAIN 模式），成功時回覆 90 並開始**雙向 relay**。  
- **BIND**：先動態取得系統分配的監聽埠 → 第一次回覆 90（告知 client 監聽埠）→ 等遠端來連 → 第二次回覆 90（帶對端 IP/Port）→ 開始 relay。  
- **Firewall**：以設定檔白名單決定是否接受（支援 `140.113.*.*` 之類的萬用字元規則），不匹配則拒絕（91）。  
- **資源管理**：`fork()` Child Process 處理工作、Parent Process 持續 `accept`；用 `SIGCHLD` 非阻塞回收避免殭屍行程。  

---
