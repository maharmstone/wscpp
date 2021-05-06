#include "wscpp.h"
#include <iostream>
#include <chrono>
#include <thread>

#if __has_include(<syncstream>)
#include <syncstream>
#define syncout std::osyncstream(std::cout)
#else
#define syncout std::cout
#endif

using namespace std;

static void msg_handler(ws::client& c, const string_view& sv, enum ws::opcode opcode) {
	if (opcode == ws::opcode::text)
		syncout << "Message from server: " << sv << endl;
}

static void disconn_handler(ws::client& c, const exception_ptr& except) {
	printf("Disconnected.\n");

	if (except) {
		try {
			rethrow_exception(except);
		} catch (const exception& e) {
			printf("Exception: %s\n", e.what());
		} catch (...) {
		}
	}
}

static void main2(const string& hostname, uint16_t port) {
	printf("Connecting to WebSocket server...\n");

	ws::client client(hostname, port, "/", msg_handler, disconn_handler);

	printf("Connected.\n");

	while (true) {
		this_thread::sleep_for(chrono::seconds(1));
	}
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		fprintf(stderr, "Usage: wsclient-test hostname port\n");
		return 1;
	}

	try {
		string hostname = argv[1];
		uint16_t port = stoul(argv[2]);

		main2(hostname, port);
	} catch (const exception& e) {
		cerr << e.what() << endl;
		return 1;
	}

	return 0;
}
