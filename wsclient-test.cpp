#include <wscpp.h>
#include <iostream>
#include <chrono>

#ifdef __MINGW32__
#include "mingw.thread.h"
#else
#include <thread>
#endif

using namespace std;

#define PORT 50000

static void msg_handler(ws::client& c, const string_view& sv, enum ws::opcode opcode) {
	if (opcode == ws::opcode::text)
		cout << "Message from server: " << sv << endl;
}

static void disconn_handler(ws::client& c) {
	printf("Disconnected.\n");
}

static void main2() {
	printf("Connecting to WebSocket server...\n");

	ws::client client("localhost", PORT, "/", msg_handler, disconn_handler);

	printf("Connected.\n");

	while (true) {
		this_thread::sleep_for(chrono::seconds(1));
	}
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
