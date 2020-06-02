#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>
#endif
#include "wscpp.h"
#include <stdint.h>
#include <map>

#ifdef __MINGW32__
#include "mingw.thread.h"
#include "mingw.shared_mutex.h"
#else
#include <thread>
#include <shared_mutex>
#endif

#ifdef _WIN32
#define SECURITY_WIN32
#include <sspi.h>
#endif

namespace ws {
	class client_thread_pimpl;

	class server_pimpl {
	public:
		server_pimpl(uint16_t port, int backlog, const server_msg_handler& msg_handler,
					 const server_conn_handler& conn_handler, const server_disconn_handler& disconn_handler,
					 bool req_auth) :
			port(port),
			backlog(backlog),
			msg_handler(msg_handler),
			conn_handler(conn_handler),
			disconn_handler(disconn_handler),
			req_auth(req_auth)
		{ }

		uint16_t port;
		int backlog;
		server_msg_handler msg_handler;
		server_conn_handler conn_handler;
		server_disconn_handler disconn_handler;
		bool req_auth;
#ifdef _WIN32
		SOCKET sock = INVALID_SOCKET;
#else
		int sock = -1;
#endif
		std::list<client_thread> client_threads;
		std::shared_mutex vector_mutex;
	};

	class client_thread_pimpl {
	public:
#ifdef _WIN32
		client_thread_pimpl(client_thread& parent, SOCKET sock, server& serv, const server_msg_handler& msg_handler,
				    const server_conn_handler& conn_handler, const server_disconn_handler& disconn_handler) :
#else
		client_thread_pimpl(client_thread& parent, int sock, server& serv, const server_msg_handler& msg_handler,
				    const server_conn_handler& conn_handler, const server_disconn_handler& disconn_handler) :
#endif
			parent(parent),
			fd(sock),
			serv(serv),
			t([](client_thread_pimpl* ctp, const server_msg_handler& msg_handler,
			     const server_conn_handler& conn_handler, const server_disconn_handler& disconn_handler) {
				ctp->msg_handler = msg_handler;
				ctp->conn_handler = conn_handler;
				ctp->disconn_handler = disconn_handler;
				ctp->run();
			}, this, msg_handler, conn_handler, disconn_handler) { }

		~client_thread_pimpl();

		void send_raw(const std::string_view& sv) const;
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
		server_msg_handler msg_handler;
		server_conn_handler conn_handler;
		server_disconn_handler disconn_handler;
		std::string recvbuf, payloadbuf;
		enum opcode last_opcode;
#ifdef _WIN32
		SOCKET fd;
		CredHandle cred_handle = {(ULONG_PTR)-1, (ULONG_PTR)-1};
		CtxtHandle ctx_handle;
		bool ctx_handle_set = false;
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
