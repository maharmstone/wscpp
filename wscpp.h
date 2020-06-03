/* Copyright (c) Mark Harmstone 2020
 *
 * This file is part of wscpp.
 *
 * wscpp is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public Licence as published by
 * the Free Software Foundation, either version 3 of the Licence, or
 * (at your option) any later version.
 *
 * wscpp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public Licence for more details.
 *
 * You should have received a copy of the GNU Lesser General Public Licence
 * along with wscpp.  If not, see <http://www.gnu.org/licenses/>. */

#pragma once

#include <string>
#include <functional>
#include <stdint.h>

#ifdef _WIN32

#ifdef WSCPP_EXPORT
#define WSCPP __declspec(dllexport)
#elif !defined(WSCPP_STATIC)
#define WSCPP __declspec(dllimport)
#else
#define WSCPP
#endif

#else

#ifdef WSCPP_EXPORT
#define WSCPP __attribute__ ((visibility ("default")))
#elif !defined(WSCPP_STATIC)
#define WSCPP __attribute__ ((dllimport))
#else
#define WSCPP
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

	class client;
	class client_thread;

	typedef std::function<void(client&, const std::string_view&, enum opcode opcode)> client_msg_handler;
	typedef std::function<void(client&)> client_disconn_handler;

	typedef std::function<void(client_thread&, const std::string_view&)> server_msg_handler;
	typedef std::function<void(client_thread&)> server_conn_handler;
	typedef std::function<void(client_thread&, const std::exception_ptr&)> server_disconn_handler;

	class sockets_error : public std::exception {
	public:
		sockets_error(const char* func);

		virtual const char* what() const noexcept {
			return msg.c_str();
		}

	private:
		int err;
		std::string msg;
	};

	class server;
	class client_thread_pimpl;

	class WSCPP client_thread {
	public:
		client_thread(void* sock, server& serv, const server_msg_handler& msg_handler,
			      const server_conn_handler& conn_handler, const server_disconn_handler& disconn_handler);
		~client_thread();
		void send(const std::string_view& payload, enum opcode opcode = opcode::text) const;
		std::string_view username() const;
		std::string_view domain_name() const;

		void* context;

		friend client_thread_pimpl;
		friend server;

	private:
		client_thread_pimpl* impl;
	};

	class server_pimpl;

	class WSCPP server {
	public:
		server(uint16_t port, int backlog, const server_msg_handler& msg_handler = nullptr,
			   const server_conn_handler& conn_handler = nullptr,
			   const server_disconn_handler& disconn_handler = nullptr,
			   bool req_auth = false);
		~server();

		void start();
		void for_each(std::function<void(client_thread&)> func);
		void close();

		friend client_thread;
		friend client_thread_pimpl;

	private:
		server_pimpl* impl;
	};

	class client_pimpl;

	class WSCPP client {
	public:
		client(const std::string& host, uint16_t port, const std::string& path, const client_msg_handler& msg_handler = nullptr,
			const client_disconn_handler& disconn_handler = nullptr);
		~client();
		void send(const std::string_view& payload, enum opcode opcode = opcode::text, unsigned int timeout = 0) const;
		void join() const;
		bool is_open() const;

	private:
		client_pimpl* impl;
	};
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
