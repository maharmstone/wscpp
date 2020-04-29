#pragma once

#include "wscpp.h"
#include <thread>

namespace ws {
	class client_pimpl {
	public:
		client_pimpl(client& parent, const std::string& host, uint16_t port, const std::string& path, const client_msg_handler& msg_handler);
		~client_pimpl();

		client& parent;
		void send_handshake();
		std::string random_key();
		void send_raw(const std::string_view& s) const;
		std::string recv_http();
		void recv_thread();
		std::string recv(unsigned int len);
		void parse_ws_message(enum opcode opcode, const std::string& payload);

		std::string host;
		uint16_t port;
		std::string path;
		client_msg_handler msg_handler;
#ifdef _WIN32
		SOCKET sock = INVALID_SOCKET;
#else
		int sock = -1;
#endif
		bool open = false;
		std::thread* t = nullptr;
		std::string payloadbuf;
		enum opcode last_opcode;
    };
}
