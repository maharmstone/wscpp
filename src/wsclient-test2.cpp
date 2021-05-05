#include "wscpp.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <syncstream>

using namespace std;

static void msg_handler(ws::client& c, const string_view& sv, enum ws::opcode opcode) {
	if (opcode == ws::opcode::text) {
		osyncstream out(cout);
		out << "Message from server: " << sv << endl;
	}
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

	vector<thread> ts;

	for (unsigned int i = 0; i < 1000; i++) {
		ts.emplace_back([&](unsigned int i) {
			try {
				bool done = false;

				ws::client client(hostname, port, "/",
						[&](ws::client& c, const string_view& sv, enum ws::opcode opcode) {
							if (opcode == ws::opcode::text) {
								osyncstream out(cout);
								out << "Message from server: " << sv << endl;
							} else if (opcode == ws::opcode::pong)
								done = true;
						},
						[&](ws::client& c, const exception_ptr& except) {
							printf("Disconnected %u.\n", i);

							if (except) {
								try {
									rethrow_exception(except);
								} catch (const exception& e) {
									printf("Propagated exception %u: %s\n", i, e.what());
								} catch (...) {
								}
							}
						});

				printf("Connected %u.\n", i);

				client.send("", ws::opcode::ping);

				while (!done) { }
			} catch (const exception& e) {
				printf("Exception %u: %s\n", i, e.what());
			}
		}, i);
	}

	for (auto& t : ts) {
		t.join();
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
