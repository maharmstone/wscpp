#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>
#endif
#include "wscpp.h"
#include "config.h"
#include <stdint.h>
#include <map>
#include <memory>
#include <atomic>
#include <optional>
#include "wsexcept.h"

#ifdef WITH_ZLIB
#include <zlib.h>
#endif

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
	class server_client_pimpl;

#ifdef _WIN32
	class wsa_event {
	public:
		wsa_event() {
			h = WSACreateEvent();
			if (h == WSA_INVALID_EVENT)
				throw formatted_error("WSACreateEvent failed (error {}).", WSAGetLastError());
		}

		~wsa_event() {
			WSACloseEvent(h);
		}

		operator WSAEVENT() {
			return h;
		}

		void reset() {
			if (!WSAResetEvent(h))
				throw formatted_error("WSAResetEvent failed (error {}).", WSAGetLastError());
		}

		void set() {
			if (!WSASetEvent(h))
				throw formatted_error("WSASetEvent failed (error {}).", WSAGetLastError());
		}

	private:
		WSAEVENT h;
	};
#endif

	class server_pimpl {
	public:
		server_pimpl(uint16_t port, int backlog, const server_msg_handler& msg_handler,
					 const server_conn_handler& conn_handler, const server_disconn_handler& disconn_handler,
					 std::string_view auth_type) :
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
		std::list<server_client> clients;
		std::recursive_mutex vector_mutex;
		std::atomic<uint64_t> last_client_id = 0;
#ifdef _WIN32
		wsa_event ev;
#endif
	};

	class server_client_pimpl {
	public:
		server_client_pimpl(server_client& parent, socket_t sock, server& serv, std::span<const uint8_t, 16> ip_addr,
							const server_msg_handler& msg_handler, const server_conn_handler& conn_handler,
							const server_disconn_handler& disconn_handler) :
			parent(parent),
			msg_handler(msg_handler),
			conn_handler(conn_handler),
			disconn_handler(disconn_handler),
			fd(sock),
			serv(serv) {
			std::copy(ip_addr.begin(), ip_addr.end(), this->ip_addr.begin());
			client_id = serv.impl->last_client_id.fetch_add(1) + 1;
		}

		~server_client_pimpl();

		void send_raw(std::span<const uint8_t> sv);
		void handle_handshake(const std::map<std::string, std::string>& headers);
		void internal_server_error(std::string_view s);
		std::string recv();
		void process_http_message(std::string_view mess);
		void process_http_messages();
#ifdef WITH_ZLIB
		void parse_ws_message(enum opcode opcode, bool rsv1, std::string_view payload);
#else
		void parse_ws_message(enum opcode opcode, std::string_view payload);
#endif
		void read();
		std::string ip_addr_string() const;
#ifdef _WIN32
		void get_username(HANDLE token);
		void impersonate() const;
		void revert() const;
		HANDLE impersonation_token() const;
#endif
#ifdef WITH_ZLIB
		std::string inflate_payload(std::span<const uint8_t> comp);
#endif

		server_client& parent;
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
		std::vector<uint8_t> sendbuf;
		uint64_t client_id;
#ifdef WITH_ZLIB
		bool deflate = false;
		std::optional<bool> last_rsv1;
		std::optional<z_stream> zstrm;
#endif

		enum class state_enum {
			http,
			websocket
		} state = state_enum::http;
	};
}
