#include <wscpp.h>
#include <iostream>

using namespace std;

#define PORT 50000
#define BACKLOG 10

static void msg_handler(ws::client_thread& c, const string_view& sv) {
	printf("Message from client %p: %.*s\n", &c, (int)sv.length(), sv.data());

	c.send("Cool story bro");
}

static void conn_handler(ws::client_thread& c) {
	printf("Client %p connected.\n", &c);

	c.send("Lemon curry?");
}

static void disconn_handler(ws::client_thread& c) {
	printf("Client %p disconnected.\n", &c);
}

static void main2() {
	ws::server serv(PORT, BACKLOG, msg_handler, conn_handler, disconn_handler, true);

	printf("Starting WebSocket server...\n");

	serv.start();

	printf("WebSocket server stopped.\n");
}

int main() {
	try {
		main2();
	} catch (const exception& e) {
		cerr << e.what() << endl;
		return 1;
	}

	return 0;
}
