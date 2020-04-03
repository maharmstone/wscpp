#pragma once

#include "wscpp.h"
#include <stdint.h>
#include <thread>
#include <map>

namespace ws {
	class client_thread_pimpl;

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

	class client_thread_pimpl {
	public:
#ifdef _WIN32
		client_thread_pimpl(client_thread& parent, SOCKET sock, server& serv, const std::function<void(client_thread&, const std::string&)>& msg_handler,
							const std::function<void(client_thread&)>& conn_handler) :
#else
		client_thread_pimpl(client_thread& parent, int sock, server& serv, const std::function<void(client_thread&, const std::string&)>& msg_handler,
							const std::function<void(client_thread&)>& conn_handler) :
#endif
			parent(parent),
			fd(sock),
			serv(serv),
			t([](client_thread* ct, const std::function<void(client_thread&, const std::string&)>& msg_handler, const std::function<void(client_thread&)>& conn_handler) {
				ct->msg_handler = msg_handler;
				ct->conn_handler = conn_handler;
				ct->run();
			}, &parent, msg_handler, conn_handler) { }

		~client_thread_pimpl();

		void send(const char* s, int length) const;
		void send(const std::string& s) const;
		void handle_handshake(std::map<std::string, std::string>& headers);
		void internal_server_error(const std::string& s);
		std::string recv(unsigned int len = 0);
		void process_http_message(const std::string& mess);
		void process_http_messages();
		void parse_ws_message(enum opcode opcode, const std::string& payload);
		void websocket_loop();
		void run();

		client_thread& parent;
		bool open = true;
		std::thread::id thread_id;
		std::string recvbuf, payloadbuf;
		enum opcode last_opcode;
#ifdef _WIN32
		SOCKET fd;
#else
		int fd;
#endif
		server& serv;
		std::thread t;

		enum class state_enum {
			http,
			websocket
		} state = state_enum::http;
	};
}
