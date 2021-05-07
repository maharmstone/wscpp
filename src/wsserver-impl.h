#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>
#endif
#include "wscpp.h"
#include <stdint.h>
#include <map>
#include <memory>

#ifdef _WIN32
#define SECURITY_WIN32
#include <sspi.h>
#else
#include <gssapi/gssapi.h>
#endif

#ifdef _WIN32
class handle_closer {
public:
	typedef HANDLE pointer;

	void operator()(HANDLE h) {
		if (h == INVALID_HANDLE_VALUE)
			return;

		CloseHandle(h);
	}
};

typedef std::unique_ptr<HANDLE, handle_closer> unique_handle;
#endif

#ifndef _WIN32
#define INVALID_SOCKET -1
#endif

namespace ws {
	class client_thread_pimpl;

	class server_pimpl {
	public:
		server_pimpl(uint16_t port, int backlog, const server_msg_handler& msg_handler,
					 const server_conn_handler& conn_handler, const server_disconn_handler& disconn_handler,
					 const std::string_view& auth_type) :
			port(port),
			backlog(backlog),
			msg_handler(msg_handler),
			conn_handler(conn_handler),
			disconn_handler(disconn_handler),
			auth_type(auth_type)
		{ }

		uint16_t port;
		int backlog;
		server_msg_handler msg_handler;
		server_conn_handler conn_handler;
		server_disconn_handler disconn_handler;
		std::string auth_type;
		socket_t sock = INVALID_SOCKET;
		std::list<client_thread> client_threads;
	};

	class client_thread_pimpl {
	public:
		client_thread_pimpl(client_thread& parent, socket_t sock, server& serv, const std::span<uint8_t, 16>& ip_addr,
							const server_msg_handler& msg_handler, const server_conn_handler& conn_handler,
							const server_disconn_handler& disconn_handler) :
			parent(parent),
			msg_handler(msg_handler),
			conn_handler(conn_handler),
			disconn_handler(disconn_handler),
			fd(sock),
			serv(serv) {
			std::copy(ip_addr.begin(), ip_addr.end(), this->ip_addr.begin());
		}

		~client_thread_pimpl();

		void send_raw(std::string_view sv) const;
		void handle_handshake(std::map<std::string, std::string>& headers);
		void internal_server_error(const std::string& s);
		std::string recv();
		void process_http_message(const std::string& mess);
		void process_http_messages();
		void parse_ws_message(enum opcode opcode, const std::string_view& payload);
		void read();
#ifdef _WIN32
		void get_username(HANDLE token);
		void impersonate() const;
		void revert() const;
		HANDLE impersonation_token() const;
#endif

		client_thread& parent;
		bool open = true;
		server_msg_handler msg_handler;
		server_conn_handler conn_handler;
		server_disconn_handler disconn_handler;
		std::string recvbuf, payloadbuf;
		enum opcode last_opcode;
		socket_t fd;
#ifdef _WIN32
		CredHandle cred_handle = {(ULONG_PTR)-1, (ULONG_PTR)-1};
		CtxtHandle ctx_handle;
		bool ctx_handle_set = false;
		unique_handle token{INVALID_HANDLE_VALUE};
#else
		gss_cred_id_t cred_handle = 0;
		gss_ctx_id_t ctx_handle = GSS_C_NO_CONTEXT;
#endif
		server& serv;
		std::array<uint8_t, 16> ip_addr;
		std::string username, domain_name;

		enum class state_enum {
			http,
			websocket
		} state = state_enum::http;
	};
}
