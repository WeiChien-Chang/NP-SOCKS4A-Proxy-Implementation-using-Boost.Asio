#include <cstdlib>
#include <iostream>
#include <fstream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <map>
#include <sstream>

using boost::asio::ip::tcp;
using namespace std;

constexpr uint8_t kSocksGranted = 90;
constexpr uint8_t kSocksRejected = 91;
static constexpr std::size_t kBufSize = 10240;

struct socks4Msg{
  int VN;
  int CD;
  string S_IP;
  string S_PORT;
  string D_IP;
  string D_PORT;
  string Command;
  string Reply;
};

class session : public std::enable_shared_from_this<session>{
  public:
    session(tcp::socket socket, boost::asio::io_context& io_context)
     : client_socket_(std::move(socket)), remote_socket_(io_context), resolver_(io_context), io_context_(io_context){}

    void start()
    {
      // 直接呼叫read_client_request()
      read_client_request();
    }

  private:
    void read_client_request()
    {
      auto self(shared_from_this());
      
      recv_buf_.fill(0);
      // 非同步讀取Client端送來的 SOCKS4_REQUEST
      client_socket_.async_read_some(boost::asio::buffer(recv_buf_), 
        [this, self](boost::system::error_code ec, std::size_t length){
          if (!ec)
          {
            // 呼叫 parse_request() 去解析 SOCKS4_REQUEST, 把 VN, CD, dstIP, dstPort, domain name 等解出來
            parse_request(int(length));

            if (request_.VN != 4) {
              close_session();
              return;
            }

            apply_firewall();

            log_request();
            reply_buf_[0] = 0;           // VN

            if(request_.Reply == "Accept"){
              reply_buf_[1] = kSocksGranted;  // CD, 90 = request granted

              if(request_.CD == 1){
                start_connect_to_remote();
              }
              else{ // CD == 2, Bind
                start_bind();
              }
            }

            else{     // Reject
              reply_buf_[1] = kSocksRejected; // CD, 91 = request rejected or failed
              write_reply_and_shutdown();
              return;
            }
          }
        }
      );
    }

    void close_session()
    {
      boost::system::error_code _;
      client_socket_.close(_);
      remote_socket_.close(_);
      // Child process 會因 io_context.run() 結束而自然 return main()
    }

    void write_reply_and_shutdown()
    {
      auto self(shared_from_this());
      boost::asio::async_write(
        client_socket_, boost::asio::buffer(reply_buf_),
        [this, self](boost::system::error_code ec, size_t length)
        {
          close_session();             // 回覆後就斷線
        });
    }
    
    void log_request() {
      std::ostringstream oss;
      oss << "<S_IP>: "    << request_.S_IP    << '\n'
          << "<S_PORT>: "  << request_.S_PORT  << '\n'
          << "<D_IP>: "    << request_.D_IP    << '\n'
          << "<D_PORT>: "  << request_.D_PORT  << '\n'
          << "<Command>: " << request_.Command << '\n'
          << "<Reply>: "   << request_.Reply   << '\n';
      std::cout << oss.str() << std::flush;
    }
    
    void start_connect_to_remote()
    {
        auto self = shared_from_this();
    
        // 1. 非同步 DNS 解析
        resolver_.async_resolve(
            request_.D_IP, request_.D_PORT,
            [this, self](const boost::system::error_code& ec,
                         tcp::resolver::results_type endpoints)
        {
            if (ec) {                           // DNS 解析失敗
                self->fail_connect("resolve: " + ec.message());
                return;
            }
    
            // 2. 非同步 connect 到遠端主機
            boost::asio::async_connect(
                remote_socket_, endpoints,
                [this, self](const boost::system::error_code& ec_conn,
                             const tcp::endpoint&)
            {
                if (ec_conn) {                  // 連線失敗
                    self->fail_connect("connect: " + ec_conn.message());
                    return;
                }
    
                reply_buf_.fill(0);
                reply_buf_[1] = kSocksGranted;  // 90
                async_write_reply_then([self] {
                    self->start_relay();             // 連線成功，開始轉送
                });
            });
        });
    }    

    void fail_connect(std::string_view reason)
    {
        reply_buf_[0] = 0;
        reply_buf_[1] = kSocksRejected;       // 91

        async_write_reply_then(
            [self = shared_from_this()]
        {
          self->close_session();
        });
    }
    
    /*
    ** BIND：讓Proxy Server先在某個Port上 Listen，等外部主機主動來連
    ** 等連上後再把資料在 client以及remote 之間雙向轉送。
    ** SOCKS4/BIND 的握手會有 兩次成功回覆 (CD=90)：
    ** 第一次 90：告訴 client, SOCKS Server 已經在某個Port listening 了，並把這個 listen Port 回報給 client（回覆 8 bytes 中的 DSTPORT 欄位）。
    ** 第二次 90：告訴 client 外部主機真的來連上我了，此時通常也會把對端的 IP/Port 回報給 client（回覆的 DSTIP/DSTPORT 填對端資訊）。
    ** 完成第二次 90 後，才開始雙向 relay。
    */
    void start_bind()
    {
        auto self = shared_from_this();
    
        // 1. 建立成員 acceptor_
        bind_acceptor_ = std::make_unique<tcp::acceptor>(
            io_context_, tcp::endpoint(tcp::v4(), 0));
        bind_acceptor_->set_option(boost::asio::socket_base::reuse_address(true));
        
        /* ----------First 90------------ */
        // 取得系統分配的 listen 埠，把它寫進 SOCKS 回覆的第 2–3 byte（DSTPORT，大端序）。
        // 這就是 第一次 90 要回的關鍵資訊：「我在哪個 port 在等」。
        uint16_t port = bind_acceptor_->local_endpoint().port();
    
        reply_buf_.fill(0);
        reply_buf_[1] = kSocksGranted;
        reply_buf_[2] = static_cast<uint8_t>(port >> 8);
        reply_buf_[3] = static_cast<uint8_t>(port & 0xFF);
        /* ----------First 90------------ */

        async_write_reply_then([self] {
            // 2. 非同步 accept 等外部主機連上來
            self->bind_acceptor_->async_accept(self->remote_socket_,
                [self](const boost::system::error_code& ec) {
                    if (ec) {
                        self->fail_bind("accept: " + ec.message());
                        return;
                    }
    
                    /* ----------Second 90------------ */
                    auto ep   = self->remote_socket_.remote_endpoint();
                    uint32_t ip   = ep.address().to_v4().to_uint();   // host-byte-order
                    uint16_t port = ep.port();

                    self->reply_buf_.fill(0);
                    self->reply_buf_[1] = kSocksGranted;
                    self->reply_buf_[2] = port >> 8;
                    self->reply_buf_[3] = port & 0xFF;
                    self->reply_buf_[4] = (ip >> 24) & 0xFF;
                    self->reply_buf_[5] = (ip >> 16) & 0xFF;
                    self->reply_buf_[6] = (ip >>  8) & 0xFF;
                    self->reply_buf_[7] =  ip        & 0xFF;
                    /* ----------Second 90------------ */

                    self->async_write_reply_then([self] {
                        self->start_relay();             // 開始資料轉發
                    });
                });
        });
    }
    
    void fail_bind(std::string_view reason)
    {
        reply_buf_.fill(0);
        reply_buf_[1] = kSocksRejected;
        async_write_reply_then(
            [self = shared_from_this()] { self->close_session(); });
    }
    
    template<class Fn>
    void async_write_reply_then(Fn&& next)
    {
        auto self = shared_from_this();
        boost::asio::async_write(
            client_socket_, boost::asio::buffer(reply_buf_),
            [self, next = std::forward<Fn>(next)](auto /*ec*/, auto /*len*/) {
                next();   // 回覆寫完後執行後續動作
            });
    }
    
    void start_relay() {           // 啟動雙向轉送
        read_from_client();
        read_from_remote();
    }
    
    /* client → remote */
    void read_from_client()
    {
        auto self = shared_from_this();
        client_socket_.async_read_some(
            boost::asio::buffer(recv_buf_),
            [self](auto ec, std::size_t n) {
                if (ec) { self->close_session(); return; }
                self->write_to_remote(n);
            });
    }
    
    void write_to_remote(std::size_t n)
    {
        auto self = shared_from_this();
        boost::asio::async_write(
            remote_socket_, boost::asio::buffer(recv_buf_, n),
            [self](auto ec, std::size_t) {
                if (ec) { self->close_session(); return; }
                self->read_from_client();
            });
    }
    
    /* remote → client */
    void read_from_remote()
    {
        auto self = shared_from_this();
        remote_socket_.async_read_some(
            boost::asio::buffer(recv_buf_),
            [self](auto ec, std::size_t n) {
                if (ec) { self->close_session(); return; }
                self->write_to_client(n);
            });
    }
    
    void write_to_client(std::size_t n)
    {
        auto self = shared_from_this();
        boost::asio::async_write(
            client_socket_, boost::asio::buffer(recv_buf_, n),
            [self](auto ec, std::size_t) {
                if (ec) { self->close_session(); return; }
                self->read_from_remote();
            });
    }

    // 判斷 IP 是否符合 pattern, e.g., pattern = "140.113.*.*", ip = "140.113.5.6" 
    static bool match_ip(const std::string& pattern, const std::string& ip)
    {
        std::array<std::string, 4> p{}, a{};
        std::istringstream(pattern) >> p[0];             // 先把整個 pattern 讀進 p[0]
        // Tips: >> 對 std::string 是以空白當分隔，所以先把 . 換成空白，>> 就能一次讀四段。
        std::replace(p[0].begin(), p[0].end(), '.', ' ');
        std::istringstream(p[0]) >> p[0] >> p[1] >> p[2] >> p[3];

        std::istringstream(ip) >> a[0];
        std::replace(a[0].begin(), a[0].end(), '.', ' ');
        std::istringstream(a[0]) >> a[0] >> a[1] >> a[2] >> a[3];

        for (size_t i = 0; i < 4; ++i)
            if (p[i] != "*" && p[i] != a[i])
                return false;
        return true;
    }

    void apply_firewall()
    {
        if (request_.Reply != "Firewall")
            return;

        request_.Reply = "Reject";

        std::ifstream conf("client_socks.conf");
        if (!conf) return;                  // 檔案不存在即全部拒絕

        std::string verb, type, pattern;
        while (conf >> verb >> type >> pattern) // e.g., permit c 140.113.*.*
        {
            if (verb != "permit")
                continue;

            if ((type == "c" && request_.CD != 1) ||      // 動作不符
                (type == "b" && request_.CD != 2))
                continue;

            if (match_ip(pattern, request_.D_IP)) {      // IP 符合
                request_.Reply = "Accept";
                return;                                   // 第一條符合即通過
            }
        }
    }
    
    // 將字串依指定分隔字元切成多段，忽略空段與 \r
    static std::vector<std::string> split_tokens(std::string_view src, char delim)
    {
        std::vector<std::string> out;
        std::string token;
        std::istringstream iss{std::string(src)};   // 轉成 stream 方便 getline
        while (std::getline(iss, token, delim)) {
            if (!token.empty() && token.back() == '\r')
                token.pop_back();
            if (!token.empty())
                out.push_back(std::move(token));
        }
        return out;
    }
    
    void parse_request(std::size_t length)
    {
        request_.Reply = "Firewall";                    // Init
        std::fill(reply_buf_.begin() + 2, reply_buf_.end(), 0); // 清零 2~7 bytes(port and IP)
    
        // SOCKS4_REQUEST 至少要有 9 byte：VN, CD, PORT(2), IP(4), \0（USERID）
        if (length < 9) { 
            request_.Reply = "Reject";
            return;
        }
    
        request_.VN = recv_buf_[0];
        if (request_.VN != 4) {                         // 非 SOCKS4 直接拒絕
            request_.Reply = "Reject";
            return;
        }
    
        request_.CD  = recv_buf_[1];
        request_.Command = (request_.CD == 1) ? "CONNECT" : "BIND"; // CD, 1 for CONNECT, 2 for BIND
        
        // DSTPORT, 2 bytes, Big-endian，轉換成字串
        uint16_t dst_port = static_cast<uint16_t>((recv_buf_[2] << 8) | recv_buf_[3]);
        request_.D_PORT  = std::to_string(dst_port);
    
        // DSTIP, 4 bytes
        // SOCKS4a，前 3 bytes 是 0，最後一byte 非 0
        bool domain_mode = (recv_buf_[4] == 0 && recv_buf_[5] == 0 &&
                            recv_buf_[6] == 0 && recv_buf_[7] != 0);
    
        if (domain_mode) {                              // SOCKS4a
            std::size_t idx = 8;
            while (idx < length && recv_buf_[idx] != 0) ++idx; // USERID 是一串以 \0 結尾的字串，一路跳到USERID的結尾
            ++idx;                                                  // 指到 domain 首字元
    
            std::string domain;
            while (idx < length && recv_buf_[idx] != 0)
                domain.push_back(recv_buf_[idx++]);       // 把 domain 字串 一直讀到 NUL 結尾為止。
    
            if (domain.empty()) {                       // domain 解析失敗
                request_.Reply = "Reject";
                return;
            }
    
            // 把DOMAIN NAME做DNS解析
            // 成功就存到 request_.D_IP，失敗就 Reject
            boost::asio::ip::tcp::resolver resolver(io_context_);
            boost::system::error_code ec;
            auto results = resolver.resolve(domain, request_.D_PORT, ec);
            if (ec) {                                   // DNS 失敗
                request_.Reply = "Reject";
                return;
            }
            request_.D_IP = results->endpoint().address().to_string();
        }

        else {                                          // 一般 IPv4
            request_.D_IP = std::to_string(recv_buf_[4]) + '.' +
                             std::to_string(recv_buf_[5]) + '.' +
                             std::to_string(recv_buf_[6]) + '.' +
                             std::to_string(recv_buf_[7]);
        }
    
        /* ---------- 來源端資訊 ---------- */
        request_.S_IP   = client_socket_.remote_endpoint().address().to_string();
        request_.S_PORT = std::to_string(client_socket_.remote_endpoint().port());
    }

    std::array<uint8_t, 8> reply_buf_;
    tcp::socket client_socket_;
    tcp::socket remote_socket_;
    tcp::resolver resolver_;
    boost::asio::io_context& io_context_;
    struct socks4Msg request_;
    std::array<uint8_t, kBufSize> recv_buf_;
    std::unique_ptr<tcp::acceptor> bind_acceptor_;
};

class server{
  public:
    server(boost::asio::io_context& io_context, unsigned short port)
     : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), io_context_(io_context), sigchld_(io_context, SIGCHLD)
    {
      acceptor_.set_option(boost::asio::socket_base::reuse_address(true));
      wait_child();
      start_accept();
    }

  private:
    // 用 async_wait 反覆回收子進程 (non-blocking waitpid)
    void wait_child()
    {
      sigchld_.async_wait(
        [this](boost::system::error_code ec, int signo)
        {
          int status;
          while (waitpid(-1, &status, WNOHANG) > 0);
          wait_child();
        });
    }
    
    void start_accept()
    {
      // async_accept 等 client 連線
      acceptor_.async_accept(
        [this](boost::system::error_code ec, tcp::socket socket)
        {
          if (!ec)
          {
            // notify_fork 在 fork() 之前呼叫，告知 Boost.Asio 做好準備，如釋放內部的 epoll/kqueue 等資源。
            io_context_.notify_fork(boost::asio::io_context::fork_prepare);

            pid_t pid = fork();
            while (pid < 0)
            {
              usleep(1000); // 等待 fork 完成
              pid = fork();
            }

            if(pid == 0) 
            {
              // 在child process中呼叫，通知 Boost.Asio 子行程需要重建/重新初始化相關資源。
              io_context_.notify_fork(boost::asio::io_context::fork_child);
              acceptor_.close();
              sigchld_.cancel();
              // 每開一個子行程就建立一個 session 物件，並開始處理請求。
              std::make_shared<session>(std::move(socket), io_context_)->start();
            }

            else if (pid > 0)
            {
              // 在父行程中呼叫，通知 Boost.Asio parent process 需要重建/重新初始化相關資源。
              io_context_.notify_fork(boost::asio::io_context::fork_parent);
              socket.close();
            }
            
            else {
              // std::cerr << "Fork error: " << strerror(errno) << '\n';
            }
          }
          start_accept();
        });
    }

    tcp::acceptor acceptor_;
    boost::asio::io_context& io_context_;
    boost::asio::signal_set sigchld_;
};

int main(int argc, char* argv[])
{
  try
  {
    if (argc != 2)
    {
      std::cerr << "Usage: ./socks_server <port>\n";
      return 1;
    }
    boost::asio::io_context io_context;
    server s(io_context, std::atoi(argv[1]));
    io_context.run();
  }
  catch (std::exception& e)
  {
    //std::cerr << "Exception: " << e.what() << "\n";
  }
  return 0;
}