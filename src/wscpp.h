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
#include <exception>
#include <array>
#include <span>
#include <any>
#include <memory>
#include <stdint.h>

#ifdef _WIN32

#include <windows.h>

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

	enum class auth {
		none,
		negotiate,
		ntlm
	};

	class client;
	class server_client;

	using client_msg_handler = std::function<void(client&, std::string_view, enum opcode opcode)>;
	using client_disconn_handler = std::function<void(client&, const std::exception_ptr&)>;

	using server_msg_handler = std::function<void(server_client&, std::string_view)>;
	using server_conn_handler = std::function<void(server_client&)>;
	using server_disconn_handler = std::function<void(server_client&, const std::exception_ptr&)>;

	class server;
	class server_client_pimpl;

#ifdef _WIN32
	using socket_t = SOCKET;
#else
	using socket_t = int;
#endif

	class WSCPP server_client {
	public:
		server_client(socket_t sock, server& serv, std::span<const uint8_t, 16> ipv6_addr, const server_msg_handler& msg_handler,
					  const server_conn_handler& conn_handler, const server_disconn_handler& disconn_handler);
		~server_client();
		void send(std::span<const uint8_t> payload, enum opcode opcode = opcode::text) const;
		std::string_view username() const;
		std::string_view domain_name() const;
		std::span<uint8_t, 16> ip_addr() const;
		std::string ip_addr_string() const;
		uint64_t client_id() const;
#ifdef _WIN32
		void impersonate() const;
		void revert() const;
		HANDLE impersonation_token() const;
#endif

		void send(std::string_view payload, enum opcode opcode = opcode::text) const {
			send(std::span((const uint8_t*)payload.data(), payload.size()), opcode);
		}

		std::any context;

		friend server;

	private:
		std::unique_ptr<server_client_pimpl> impl;
	};

	class server_pimpl;

	class WSCPP server {
	public:
		server(uint16_t port, int backlog, const server_msg_handler& msg_handler = nullptr,
			   const server_conn_handler& conn_handler = nullptr,
			   const server_disconn_handler& disconn_handler = nullptr,
			   auth auth_type = auth::none);
		~server();

		void start();
		void for_each(std::function<bool(server_client&)> func);
		bool find_client(uint64_t client_id, const std::function<void(server_client&)>& func) const;
		bool send_to_client(uint64_t client_id, std::span<const uint8_t> payload, enum opcode opcode = opcode::text) const noexcept;
		void close();

		bool send_to_client(uint64_t client_id, std::string_view payload, enum opcode opcode = opcode::text) const noexcept {
			return send_to_client(client_id, std::span((const uint8_t*)payload.data(), payload.size()), opcode);
		}

		friend server_client;
		friend server_client_pimpl;

		std::unique_ptr<server_pimpl> impl;
	};

	class client_pimpl;

	class WSCPP client {
	public:
		client(std::string_view host, uint16_t port, std::string_view path, const client_msg_handler& msg_handler = nullptr,
			   const client_disconn_handler& disconn_handler = nullptr, bool enc = false);
		~client();
		void send(std::span<const uint8_t> payload, enum opcode opcode = opcode::text, unsigned int timeout = 0) const;
		void join() const;
		bool is_open() const;
		void ping(unsigned int timeout_ms = 0) const;

		void send(std::string_view payload, enum opcode opcode = opcode::text, unsigned int timeout = 0) const {
			send(std::span((const uint8_t*)payload.data(), payload.size()), opcode, timeout);
		}

	private:
		std::unique_ptr<client_pimpl> impl;
	};
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
