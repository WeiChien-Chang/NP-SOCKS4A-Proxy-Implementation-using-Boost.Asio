all:socks_server.cpp console.cpp
	g++ socks_server.cpp -o socks_server
	g++ console.cpp -o pj5.cgi

clean:
	rm -f socks_server pj5.cgi