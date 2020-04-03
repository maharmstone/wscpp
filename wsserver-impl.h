#pragma once

#include "wscpp.h"
#include <stdint.h>

namespace ws {
	class server_pimpl {
	public:
		server_pimpl(uint16_t port, int backlog, const std::function<void(client_thread&, const std::string&)>& msg_handler,
					 const std::function<void(client_thread&)>& conn_handler) :
			port(port),
			backlog(backlog),
			msg_handler(msg_handler),
			conn_handler(conn_handler)
		{ }

		uint16_t port;
		int backlog;
		std::function<void(client_thread&, const std::string&)> msg_handler;
		std::function<void(client_thread&)> conn_handler;
#ifdef _WIN32
		SOCKET sock = INVALID_SOCKET;
#else
		int sock = -1;
#endif
		std::list<client_thread> client_threads;
		std::shared_timed_mutex vector_mutex;
	};
}
