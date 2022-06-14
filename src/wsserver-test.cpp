#include "wscpp.h"
#include <iostream>
#include <string.h>
#include <memory>

#if __has_include(<syncstream>)
#include <syncstream>
#define syncout std::osyncstream(std::cout)
#else
#define syncout std::cout
#endif

using namespace std;

#define BACKLOG 4096

static void msg_handler(ws::server_client& c, string_view sv) {
	const auto& username = c.username();
	const auto& domain_name = c.domain_name();

	if (!username.empty())
		syncout << "Message from client " << c.client_id() << " (" << domain_name << "\\" << username << "): " << sv << endl;
	else
		syncout << "Message from client " << c.client_id() << ": " << sv << endl;

	try {
		c.send("Cool story bro");
	} catch (const exception& e) {
		cerr << e.what() << endl;
	}
}

static void conn_handler(ws::server& serv, ws::server_client& c) {
	const auto& username = c.username();
	const auto& domain_name = c.domain_name();

	if (!username.empty())
		syncout << "Client " << c.client_id() << " (" << domain_name << "\\" << username << ") connected (" << c.ip_addr_string() << ")." << endl;
	else
		syncout << "Client " << c.client_id() << " connected (" << c.ip_addr_string() << ")." << endl;

	serv.for_each([&](ws::server_client& ct) {
		ct.send("new client");

		return true;
	});

	try {
		c.send("Lemon curry?");
	} catch (const exception& e) {
		cerr << e.what() << endl;
	}
}

static void disconn_handler(ws::server_client& c, const exception_ptr& except) {
	const auto& username = c.username();
	const auto& domain_name = c.domain_name();

	if (!username.empty())
		syncout << "Client " << c.client_id() << " (" << domain_name << "\\" << username << ") disconnected." << endl;
	else
		syncout << "Client " << c.client_id() << " disconnected." << endl;

	if (except) {
		try {
			rethrow_exception(except);
		} catch (const exception& e) {
			syncout << "Exception: " << e.what() << endl;
		} catch (...) {
		}
	}
}

static void main2(uint16_t port) {
	ws::server serv(port, BACKLOG, msg_handler,
					[&](ws::server_client& c) {
						conn_handler(serv, c);
					},
					disconn_handler, "Negotiate");

	printf("Starting WebSocket server...\n");

	serv.start();

	printf("WebSocket server stopped.\n");
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: wsserver-test port\n");
		return 1;
	}

	try {
		uint16_t port = stoul(argv[1]);

		main2(port);
	} catch (const exception& e) {
		cerr << e.what() << endl;
		return 1;
	}

	return 0;
}
