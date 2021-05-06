#include "wscpp.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <condition_variable>

#if __has_include(<syncstream>)
#include <syncstream>
#define syncout std::osyncstream(std::cout)
#else
#define syncout std::cout
#endif

using namespace std;

static void main2(const string& hostname, uint16_t port) {
	unsigned int num_connected = 0, num_disconnected = 0;

	constexpr unsigned int num_threads = 1000;

	syncout << "Connecting to WebSocket server..." << endl;

	vector<thread> ts;

	for (unsigned int i = 0; i < num_threads; i++) {
		ts.emplace_back([&](unsigned int i) {
			try {
				condition_variable cv;
				mutex m;
				bool done = false;

				ws::client client(hostname, port, "/",
						[&](ws::client& c, const string_view& sv, enum ws::opcode opcode) {
							if (opcode == ws::opcode::text)
								syncout << "Message from server (" << i << "): " << sv << endl;
							else if (opcode == ws::opcode::pong) {
								{
									lock_guard<mutex> lk(m);
									done = true;
								}

								cv.notify_one();
							}
						},
						[&](ws::client& c, const exception_ptr& except) {
							num_disconnected++;
							syncout << "Disconnected " << i << " (" << num_disconnected << "/" << num_threads << ")." << endl;

							if (except) {
								try {
									rethrow_exception(except);
								} catch (const exception& e) {
									syncout << "Propagated exception " << i << ": " << e.what() << endl;
								} catch (...) {
								}
							}
						});

				num_connected++;
				syncout << "Connected " << i << " (" << num_connected << "/" << num_threads << ")." << endl;

				client.send("", ws::opcode::ping);

				{
					unique_lock<mutex> lk(m);
					cv.wait(lk, [&]{ return done; });
				}
			} catch (const exception& e) {
				syncout << "Exception " << i << ": " << e.what() << endl;
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
