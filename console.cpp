#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include <array>
#include <regex>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

using boost::asio::ip::tcp;
using namespace std;

std::array<std::string, 5> host, port, file;
std::string socks_host, socks_port;

/* ---------------Parse Query String----------------- */
/* 
** /console.cgi?h0=nplinux1&p0=12345&f0=t1.txt&h1=nplinux2&p1=22222&f1=t2.txt&sh=127.0.0.1&sp=1080
** 解析出"?"後面的 query string，就可以知道要連到哪些 host / port
*/
void parse_query_string()
{
  char* query_Cstring = getenv("QUERY_STRING");  // getenv 直接回傳 指向環境變數的 C‑string
  if (query_Cstring == nullptr)
  {
    std::cerr << "QUERY_STRING not found\n";
    return;
  }
  std::string query_string = query_Cstring;

  // 由於query string有固定格式，這邊以regular expression來解析
  // key=value pair之間以 & 分隔
  std::regex kv(R"(([hpf])(\d)=([^&]*))");  // h0 / p3 / f2
  std::regex sx(R"(s([hp])=([^&]*))");  // sh / sp(SOCKS host / port)
  std::smatch match;  // 針對 std::string 做正則搜尋時存放「比對結果」的容器
  auto iterator = query_string.cbegin();

  while(std::regex_search(iterator, query_string.cend(), match, kv)) {
    /* 
    ** m 內會得到 3 個 capture group
    ** m[1] = h / p / f      代表是哪一種欄位
    ** m[2] = 0‥4            數字，用來決定 index
    ** m[3] = value          = 後面直到 & 之前的內容
    */
    int index = match[2].str()[0] - '0';  // 取得 index
    std::string value = match[3];  // 取得 value

    switch (match[1].str()[0]) {
      case 'h':
        host[index] = value;
        break;
      case 'p':
        port[index] = value;
        break;
      case 'f':
        file[index] = value;
        break;
    }
    iterator = match.suffix().first;  // 更新 iterator，讓下一次的 regex_search 從這裡開始
  }

  iterator = query_string.cbegin();
  while (std::regex_search(iterator, query_string.cend(), match, sx)) {
      // s'h'
      if (match[1] == "h")
          socks_host = match[2];
      // s'p'
      else
          socks_port = match[2];
          
      iterator = match.suffix().first;
  }
}

/* -----------HTML escape & newLine取代-------------- */
/*
** Shell 輸出可能含 <, >, &, ', 若直接插入 <script> 會破版或 XSS。
** 這邊做 HTML escape，將 <, >, &, ', " 轉成 &lt;, &gt;, &amp;, &#39;, &quot;
** 另外CGI 規定要把 \n 換成 &NewLine;，才能在 <pre> 內正常斷行而不關閉 <script> 字串。
** 將 \n 取代成 &NewLine;，正確顯示換行
*/
std::string html_escape(std::string str)
{
  std::string out;
  for (char c : str)
  {
    switch (c)
    {
      case '<':
        out += "&lt;";
        break;
      case '>':
        out += "&gt;";
        break;
      case '&':
        out += "&amp;";
        break;
      case '\'':
        out += "&#39;";
        break;
      case '\"':
        out += "&quot;";
        break;
      default:
        out.push_back(c);
    }
  }
  return out;
}

void replace_newLine(std::string& str)
{
  size_t pos = 0;
  while ((pos = str.find('\n', pos)) != std::string::npos)
  {
    str.replace(pos, 1, "&NewLine;");
    pos += 8;  // length of "&NewLine;"
  }
}

class Client
  : public std::enable_shared_from_this<Client>
{
public:
  // Constructor
  Client(boost::asio::io_context& io_context, int id)
    : resolver_(io_context), socket_(io_context), id_(id), first_prompt_(true)
  {
  }

  void start()
  {
    if (host[id_].empty())
        return;

    fin_.open("./test_case/" + file[id_]);

    auto self = shared_from_this();
    // 非同步解析 SOCKS 伺服器的 IP / Port
    resolver_.async_resolve(socks_host, socks_port,
        [this, self](boost::system::error_code ec, tcp::resolver::results_type eps) {
            if (!ec) {
                boost::asio::async_connect(socket_, eps,
                    [this, self](boost::system::error_code ec, auto) {
                        if (!ec)
                            send_socks_request();
                    });
            }
        });
  }

private:
  // do_read()
  // 持續收 Shell 輸出 -> output_shell() 寫入網頁。
  // 遇到 % Prompt 才代表 Shell 就緒，再送下一行指令。
  void do_read()
  {
    auto self(shared_from_this());
    socket_.async_read_some(boost::asio::buffer(data_, max_length),
        [this, self](boost::system::error_code ec, std::size_t length)
        {
          if (!ec)
          {
            std::string str(self->data_, length);
            self->output_shell(str);
            if (str.find("% ") != std::string::npos)
            {
              if (first_prompt_)
              {
                first_prompt_ = false;
                send_who();
              }
              else
              {
                self->do_write();
              }
            }
            
            self->do_read();
          }
        });
  }

  // 組成 SOCK4A CONNECT Request，非同步送給 SOCKS Proxy
  void send_socks_request()
  {
      std::vector<uint8_t> pkt;

      if (port[id_].empty()) return;

      pkt.reserve(9 + host[id_].size());
  
      pkt.push_back(0x04);                     // VN = 4, SOCKS protocol version number.
      pkt.push_back(0x01);                     // CD = CONNECT, SOCKS command code for CONNECT request.
      
      // DSTPORT, 2 bytes, Big-endian
      // port是字串，透過string to int 轉成16-bit integer
      // 拆成兩個 byte 放入 pkt， p >> 8 -> 高 8 bits, p & 0xFF -> 低 8 bits
      uint16_t p = std::stoi(port[id_]);
      pkt.push_back(p >> 8);
      pkt.push_back(p & 0xFF);
  
      // SOCKS4A: DSTIP=0.0.0.x，x要是非0，DOMAIN 後面再放
      pkt.insert(pkt.end(), {0,0,0,1});        // 4 bytes

      // USERID 可放空字串
      pkt.push_back(0x00);                     // USERID terminator
  
      for(char c: host[id_]) pkt.push_back(c); // DOMAIN name

      // NULL 結尾
      pkt.push_back(0x00);
  
      auto self = shared_from_this();
      boost::asio::async_write(socket_, boost::asio::buffer(pkt),
          [this, self](auto ec, auto){
              if (!ec) recv_socks_reply();
          });
  }
  
  // 收 SOCKS Proxy 回覆，確認是否成功
  // 成功就切回原本的 do_read() 流程
  // 0 90 0 0 0 0 0 0 for connect, DSTPORT and DSTIP fields are ignored in CONNECT reply.
  void recv_socks_reply()
  {
      auto self = shared_from_this();
      boost::asio::async_read(socket_, boost::asio::buffer(reply_buf_),   // 8 bytes
          [this, self](auto ec, auto){
              if (!ec && reply_buf_[1] == 0x5A) {     // 90 = request granted
                  do_read();
              }
              else {
                socket_.close();                     // 91 = request rejected or failed
              }
          });
  }

  void do_write()
  {
    std::string cmd;
    if(!std::getline(fin_, cmd))
      return;
    
    cmd = cmd + '\n';
    output_command(cmd);

    auto self = shared_from_this();
    boost::asio::async_write(socket_, boost::asio::buffer(cmd),
        [this, self](boost::system::error_code ec, std::size_t)
        {
        });
  }

  void output_shell(std::string str)
  {
    str.erase(std::remove(str.begin(), str.end(), '\r'), str.end());
    str = html_escape(std::move(str));
    replace_newLine(str);
    std::cout << "<script>"
              << "document.getElementById('s" << id_ << "').innerHTML+='"
              << str << "';</script>";
    std::cout.flush();  // flush() 立刻送到瀏覽器，確保畫面即時更新
  }
  
  void output_command(std::string str)
  {
    str.erase(std::remove(str.begin(), str.end(), '\r'), str.end());
    str = html_escape(std::move(str));
    replace_newLine(str);
    std::cout << "<script>"
              << "document.getElementById('s" << id_ << "').innerHTML+='<b>"
              << str << "</b>';</script>";
    std::cout.flush();
  }

  void send_who()
  {
    std::string cmd = "who\n";
    output_command(cmd);
    auto self = shared_from_this();
    boost::asio::async_write(socket_, boost::asio::buffer(cmd),
        [this, self](boost::system::error_code ec, auto)
        {
        });
  }

  std::array<uint8_t, 8> reply_buf_;
  tcp::resolver resolver_;
  tcp::socket   socket_;
  std::ifstream fin_;
  int id_;
  enum { max_length = 1024 };
  char data_[max_length];
  bool first_prompt_;
};

void print_html()
{
  std::cout << "Content-Type: text/html\r\n\r\n";
  std::cout << R"(
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <title>NP Project 3 Sample Console</title>
      <link
        rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css"
        integrity="sha384-TX8t27EcRE3e/ihU7zmQxVncDAy5uIKz4rEkgIXeMed4M0jlfIDPvg6uqKI2xXr2"
        crossorigin="anonymous"
      />
      <link
        href="https://fonts.googleapis.com/css?family=Source+Code+Pro"
        rel="stylesheet"
      />
      <link
        rel="icon"
        type="image/png"
        href="https://cdn0.iconfinder.com/data/icons/small-n-flat/24/678068-terminal-512.png"
      />
      <style>
        * {
          font-family: 'Source Code Pro', monospace;
          font-size: 1rem !important;
        }
        body {
          background-color: #212529;
        }
        pre {
          color: #cccccc;
        }
        b {
          color: #01b468;
        }
      </style>
    </head>
    <body>
      <table class="table table-dark table-bordered">
        <thead>
          <tr>
  )";
  for (int i = 0; i < 5; ++i) {
    if (!host[i].empty())
        std::cout << "          <th scope=\"col\">" << host[i] << ':' << port[i] << "</th>";
  }
  std::cout << R"(
          </tr>
        </thead>
        <tbody>
          <tr>
  )";

  for (int i = 0; i < 5; ++i) {
    if (!host[i].empty())
        std::cout << "          <td><pre id=\"s" << i << "\" class=\"mb-0\"></pre></td>";
  }

  std::cout << R"(
          </tr>
        </tbody>
      </table>
    </body>
  </html>
  )";

  std::cout.flush();  // 立刻送到瀏覽器
}

int main(int argc, char* argv[])
{
  try
  {
    parse_query_string();  // 解析 QUERY_STRING
    print_html();  // 輸出 HTML 頁面

    boost::asio::io_context io_context;

    std::vector<std::shared_ptr<Client>> clients;
    for (int i = 0; i < 5; ++i) {
        if (host[i].empty())
          continue;
        auto c = std::make_shared<Client>(io_context, i);
        clients.push_back(c);
        c->start();
    }
    io_context.run();
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}