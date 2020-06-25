#pragma once

#include "wscpp.h"

#ifdef __MINGW32__
#include "mingw.thread.h"
#else
#include <thread>
#endif

#ifdef _WIN32
#define SECURITY_WIN32
#include <sspi.h>
#endif

namespace ws {
	class client_pimpl {
	public:
		client_pimpl(client& parent, const std::string& host, uint16_t port, const std::string& path,
			     const client_msg_handler& msg_handler, const client_disconn_handler& disconn_handler);
		~client_pimpl();

		void open_connexion();
		void send_auth_response(const std::string_view& auth_type, const std::string_view& auth_msg, const std::string& req);
		void send_handshake();
		std::string random_key();
		void send_raw(const std::string_view& s, unsigned int timeout = 0) const;
		void set_send_timeout(unsigned int timeout) const;
		std::string recv_http();
		void recv_thread();
		std::string recv(unsigned int len);
		void parse_ws_message(enum opcode opcode, const std::string& payload);

		client& parent;
		std::string host;
		uint16_t port;
		std::string path;
		client_msg_handler msg_handler;
		client_disconn_handler disconn_handler;
#ifdef _WIN32
		SOCKET sock = INVALID_SOCKET;
		CredHandle cred_handle = {(ULONG_PTR)-1, (ULONG_PTR)-1};
		CtxtHandle ctx_handle;
		bool ctx_handle_set = false;
#else
		int sock = -1;
		gss_cred_id_t cred_handle = 0;
		gss_ctx_id_t ctx_handle = GSS_C_NO_CONTEXT;
#endif
		bool open = false;
		std::thread* t = nullptr;
		std::string payloadbuf;
		std::string fqdn;
		enum opcode last_opcode;
    };
}
