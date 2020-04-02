#pragma once

#ifdef _WIN32
#include <WinSock2.h>
#include <ws2ipdef.h>
#endif
#include <map>
#include <string>
#include <thread>
#include <iostream>
#include <functional>
#include <shared_mutex>
#include <list>
#include <stdint.h>

#ifdef _WIN32

#ifdef WSCPP_EXPORT
#define WSCPP __declspec(dllexport)
#else
#define WSCPP __declspec(dllimport)
#endif

#else

#ifdef WSCPP_EXPORT
#define WSCPP __attribute__ ((visibility ("default")))
#else
#define WSCPP __attribute__ ((dllimport))
#endif

#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

namespace ws {
	enum class opcode : uint8_t {
		invalid = 0,
		text = 1,
		binary = 2,
		close = 8,
		ping = 9,
		pong = 10
	};

	class sockets_error : public std::exception {
	public:
#ifdef _WIN32
		sockets_error(const char* func) : err(WSAGetLastError()), msg(std::string(func) + " failed (error " + std::to_string(err) + ")") {
#else
			sockets_error(const char* func) : err(errno), msg(std::string(func) + " failed (error " + std::to_string(err) + ")") {
#endif
		}

		virtual const char* what() const noexcept {
			return msg.c_str();
		}

	private:
		int err;
		std::string msg;
	};


	class server;
	class client_thread;

	typedef void (*ws_conn)(client_thread&);

	class WSCPP client_thread {
	public:
#ifdef _WIN32
		client_thread(SOCKET sock, server& serv, const std::function<void(client_thread&, const std::string&)>& msg_handler = nullptr,
					  const std::function<void(client_thread&)>& conn_handler = nullptr) :
#else
		client_thread(int sock, server& serv, const std::function<void(client_thread&, const std::string&)>& msg_handler = nullptr,
			  const std::function<void(client_thread&)>& conn_handler = nullptr) :
#endif
			fd(sock),
			serv(serv),
			t([](client_thread* ct, const std::function<void(client_thread&, const std::string&)>& msg_handler, const std::function<void(client_thread&)>& conn_handler) {
			ct->msg_handler = msg_handler;
			ct->conn_handler = conn_handler;
			ct->run();
			}, this, msg_handler, conn_handler) { }

		~client_thread();
		void run();
		void send_ws_message(enum opcode opcode, const std::string& payload) const;

		std::thread::id thread_id;
		std::function<void(client_thread&, const std::string&)> msg_handler;
		std::function<void(client_thread&)> conn_handler;

		enum class state_enum {
			http,
			websocket
		} state = state_enum::http;

	private:
		void send(const char* s, int length) const;
		void send(const std::string& s) const;
		void handle_handshake(std::map<std::string, std::string>& headers);
		void internal_server_error(const std::string& s);
		std::string recv(unsigned int len = 0);
		void process_http_message(const std::string& mess);
		void process_http_messages();
		void parse_ws_message(enum opcode opcode, const std::string& payload);
		void websocket_loop();

		bool open = true;
		std::string recvbuf, payloadbuf;
		enum opcode last_opcode;
#ifdef _WIN32
		SOCKET fd;
#else
		int fd;
#endif
		server& serv;
		std::thread t;
	};

	class WSCPP server {
	public:
		server(uint16_t port, int backlog, const std::function<void(client_thread&, const std::string&)>& msg_handler = nullptr,
			   const std::function<void(client_thread&)>& conn_handler = nullptr) :
			port(port),
			backlog(backlog),
			msg_handler(msg_handler),
			conn_handler(conn_handler)
		{ }

		void start();
		void for_each(std::function<void(client_thread&)> func);
		void close();

		friend client_thread;

	private:
		uint16_t port;
		int backlog;
		std::function<void(client_thread&, const std::string&)> msg_handler;
		std::function<void(client_thread&)> conn_handler;
#ifdef _WIN32
		SOCKET sock = INVALID_SOCKET;
#else
		int sock = -1;
#endif
		bool running = true;
		std::list<client_thread> client_threads;
		std::shared_timed_mutex vector_mutex;
	};

	class WSCPP client {
	public:
		client(const std::string& host, uint16_t port, const std::string& path, const std::function<void(client&, const std::string&)>& msg_handler = nullptr);
		~client();
		void send_ws_message(enum opcode opcode, const std::string_view& payload) const;
		void join() const;
		bool is_open() const;

	private:
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
		std::function<void(client&, const std::string&)> msg_handler;
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

#ifdef _MSC_VER
#pragma warning(pop)
#endif
