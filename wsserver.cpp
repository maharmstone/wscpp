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

#include <string>
#include <list>
#include <shared_mutex>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#endif
#include <fcntl.h>
#include <string.h>
#include "wscpp.h"
#include "wsserver-impl.h"
#include "b64.h"
#include "sha1.h"

using namespace std;

#define MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static string lower(string s) {
	for (auto& c : s) {
		if (c >= 'A' && c <= 'Z')
			c += 'a' - 'A';
	}

	return s;
}

namespace ws {
	client_thread::~client_thread() {
#ifdef _WIN32
		if (fd != SOCKET_ERROR)
			closesocket(fd);
#else
		if (fd != -1)
			close(fd);
#endif

		t.join();
	}

	void client_thread::run() {
		thread_id = this_thread::get_id();

		while (open && state == state_enum::http) {
			recvbuf += recv();

			process_http_messages();
		}

		if (open && state == state_enum::websocket) {
			try {
				websocket_loop();
			} catch (...) {
			}
		}

		thread del_thread([&]() {
			unique_lock<shared_timed_mutex> guard(serv.impl->vector_mutex);

			for (auto it = serv.impl->client_threads.begin(); it != serv.impl->client_threads.end(); it++) {
				if (it->thread_id == thread_id) {
					serv.impl->client_threads.erase(it);
					break;
				}
			}
		});

		del_thread.detach();
	}

	void client_thread::send_ws_message(enum opcode opcode, const string& payload) const {
		char* msg;
		size_t msglen, len = payload.length();

		msglen = len + 2;

		if (len > 125 && len < 0x10000)
			msglen += 2;
		else if (len >= 0x10000)
			msglen += 8;

		msg = new char[msglen];

		try {
			msg[0] = 0x80 | ((uint8_t)opcode & 0xf);

			if (len <= 125) {
				msg[1] = (char)len;
				memcpy(msg + 2, payload.c_str(), len);
			} else if (len < 0x10000) {
				msg[1] = 126;
				msg[2] = (len & 0xff00) >> 8;
				msg[3] = len & 0xff;
				memcpy(msg + 4, payload.c_str(), len);
			} else {
				msg[1] = 127;
				msg[2] = (char)((len & 0xff00000000000000) >> 56);
				msg[3] = (char)((len & 0xff000000000000) >> 48);
				msg[4] = (char)((len & 0xff0000000000) >> 40);
				msg[5] = (char)((len & 0xff00000000) >> 32);
				msg[6] = (char)((len & 0xff000000) >> 24);
				msg[7] = (char)((len & 0xff0000) >> 16);
				msg[8] = (char)((len & 0xff00) >> 8);
				msg[9] = len & 0xff;
				memcpy(msg + 10, payload.c_str(), len);
			}

			send(msg, (int)msglen);
		} catch (...) {
			delete[] msg;
			throw;
		}

		delete[] msg;
	}

	void client_thread::send(const char* s, int length) const {
#ifdef _WIN32
		u_long mode = 1;

		if (ioctlsocket(fd, FIONBIO, &mode) != 0)
			throw runtime_error("ioctlsocket failed (" + to_string(WSAGetLastError()) + ").");
#else
		int flags = fcntl(fd, F_GETFL, 0);

		if (flags == -1)
			throw runtime_error("fcntl returned -1");

		flags |= O_NONBLOCK;

		if (fcntl(fd, F_SETFL, flags) != 0)
			throw runtime_error("fcntl failed");
#endif

		int bytes = ::send(fd, s, length, 0);

#ifdef _WIN32
		if (bytes == SOCKET_ERROR) {
			int err = WSAGetLastError();

			if (err != WSAEWOULDBLOCK)
				throw runtime_error("send failed (" + to_string(err) + ").");
		}

		mode = 0;

		if (ioctlsocket(fd, FIONBIO, &mode) != 0)
			throw runtime_error("ioctlsocket failed (" + to_string(WSAGetLastError()) + ").");
#else
		if (bytes == -1) {
			int err = errno;

			if (err != EWOULDBLOCK)
				throw runtime_error("send failed (" + to_string(err) + ").");
		}

		flags &= ~O_NONBLOCK;

		if (fcntl(fd, F_SETFL, flags) != 0)
			throw runtime_error("fcntl failed");
#endif
	}

	void client_thread::send(const string& s) const {
		send(s.c_str(), (int)s.length());
	}

	void client_thread::handle_handshake(map<string, string>& headers) {
		if (headers.count("Upgrade") == 0 || lower(headers["Upgrade"]) != "websocket" || headers.count("Sec-WebSocket-Key") == 0 || headers.count("Sec-WebSocket-Version") == 0) {
			send("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
			return;
		}

		unsigned int version = stoul(headers["Sec-WebSocket-Version"]);

		if (version > 13) {
			send("HTTP/1.1 400 Bad Request\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\n\r\n");
			return;
		}

		string resp = b64encode(sha1(headers["Sec-WebSocket-Key"] + MAGIC_STRING));

		send("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + resp + "\r\n\r\n");

		state = state_enum::websocket;
		recvbuf = "";

		if (conn_handler)
			conn_handler(*this);
	}

	void client_thread::internal_server_error(const string& s) {
		try {
			send("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: " + to_string(s.size()) + "\r\n\r\n" + s);
		} catch (...) {
		}
	}

	string client_thread::recv(unsigned int len) {
		char s[4096];
		int bytes, err = 0;

		if (len == 0)
			len = sizeof(s);

		do {
			bytes = ::recv(fd, s, len, 0);

#ifdef _WIN32
			if (bytes == SOCKET_ERROR)
				err = WSAGetLastError();
		} while (bytes == SOCKET_ERROR && err == WSAEWOULDBLOCK);
#else
			if (bytes == -1)
				err = errno;
		} while (bytes == -1 && err == EWOULDBLOCK);
#endif

#ifdef _WIN32
		if (bytes == SOCKET_ERROR)
#else
		if (bytes == -1)
#endif
			throw runtime_error("recv failed (" + to_string(err) + ").");
		else if (bytes == 0) {
			open = false;
			return "";
		}

		return string(s, bytes);
	}

	void client_thread::process_http_message(const string& mess) {
		bool first = true;
		size_t nl = mess.find("\r\n"), nl2 = 0;
		string verb, path;
		map<string, string> headers;

		do {
			if (first) {
				size_t space = mess.find(" ");

				if (space == string::npos || space > nl)
					verb = mess.substr(0, nl);
				else {
					verb = mess.substr(0, space);

					size_t space2 = mess.find(" ", space + 1);

					if (space2 == string::npos || space2 > nl)
						path = mess.substr(space + 1, nl - space - 1);
					else
						path = mess.substr(space + 1, space2 - space - 1);
				}

				first = false;
			} else {
				size_t colon = mess.find(": ", nl2);

				if (colon != string::npos)
					headers.emplace(mess.substr(nl2, colon - nl2), mess.substr(colon + 2, nl - colon - 2));
			}

			nl2 = nl + 2;
			nl = mess.find("\r\n", nl2);
		} while (nl != string::npos);

		size_t qm = path.find("?");
		if (qm != string::npos)
			path = path.substr(0, qm);

		if (path != "/")
			send("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
		else if (verb != "GET")
			send("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
		else {
			try {
				handle_handshake(headers);
			} catch (const exception& e) {
				internal_server_error(e.what());
			} catch (...) {
				internal_server_error("Unhandled exception.");
			}
		}
	}

	void client_thread::process_http_messages() {
		do {
			size_t dnl = recvbuf.find("\r\n\r\n");

			if (dnl == string::npos)
				return;

			process_http_message(recvbuf.substr(0, dnl + 2));

			if (state != state_enum::http)
				break;

			recvbuf = recvbuf.substr(dnl + 4);
		} while (true);
	}

	void client_thread::parse_ws_message(enum opcode opcode, const string& payload) {
		switch (opcode) {
			case opcode::close:
				open = false;
				return;

			case opcode::ping:
				send_ws_message(opcode::pong, payload);
				break;

			case opcode::text: {
				if (msg_handler)
					msg_handler(*this, payload);

				break;
			}

			default:
				break;
		}
	}

	void client_thread::websocket_loop() {
		while (open) {
			string header = recv(2);

			if (!open)
				break;

			bool fin = (header[0] & 0x80) != 0;
			auto opcode = (enum opcode)(uint8_t)(header[0] & 0xf);
			bool mask = (header[1] & 0x80) != 0;
			uint64_t len = header[1] & 0x7f;

			if (len == 126) {
				string extlen = recv(2);

				if (!open)
					break;

				len = ((uint8_t)extlen[0] << 8) | (uint8_t)extlen[1];
			} else if (len == 127) {
				string extlen = recv(8);

				if (!open)
					break;

				len = (uint8_t)extlen[0];
				len <<= 8;
				len |= (uint8_t)extlen[1];
				len <<= 8;
				len |= (uint8_t)extlen[2];
				len <<= 8;
				len |= (uint8_t)extlen[3];
				len <<= 8;
				len |= (uint8_t)extlen[4];
				len <<= 8;
				len |= (uint8_t)extlen[5];
				len <<= 8;
				len |= (uint8_t)extlen[6];
				len <<= 8;
				len |= (uint8_t)extlen[7];
			}

			string mask_key;
			if (mask) {
				mask_key = recv(4);

				if (!open)
					break;
			}

			string payload = len == 0 ? "" : recv((unsigned int)len);

			if (!open)
				break;

			if (mask) {
				for (unsigned int i = 0; i < payload.length(); i++) {
					payload[i] ^= mask_key[i % 4];
				}
			}

			if (!fin) {
				if (opcode != opcode::invalid)
					last_opcode = opcode;

				payloadbuf += payload;
			} else if (payloadbuf != "") {
				parse_ws_message(last_opcode, payloadbuf + payload);
				payloadbuf = "";
			} else
				parse_ws_message(opcode, payload);
		}
	}

	void server::start() {
#ifdef _WIN32
		WSADATA wsaData;

		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
			throw runtime_error("WSAStartup failed.");
#endif

		try {
			struct sockaddr_in6 myaddr;

			memset(&myaddr, 0, sizeof(myaddr));
			myaddr.sin6_family = AF_INET6;
			myaddr.sin6_port = htons(impl->port);
			myaddr.sin6_addr = in6addr_any;

			impl->sock = socket(AF_INET6, SOCK_STREAM, 0);

#ifdef _WIN32
			if (impl->sock == INVALID_SOCKET)
#else
			if (impl->sock == -1)
#endif
				throw runtime_error("socket failed.");

			try {
				int reuseaddr = 1;
				int ipv6only = 0;

#ifdef _WIN32
				if (setsockopt(impl->sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&reuseaddr), sizeof(int)) == SOCKET_ERROR)
					throw sockets_error("setsockopt");

				if (setsockopt(impl->sock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&ipv6only), sizeof(int)) == SOCKET_ERROR)
					throw sockets_error("setsockopt");

				if (::bind(impl->sock, reinterpret_cast<sockaddr*>(&myaddr), sizeof(myaddr)) == SOCKET_ERROR)
					throw sockets_error("bind");

				if (listen(impl->sock, backlog) == SOCKET_ERROR)
					throw sockets_error("listen");
#else
				if (setsockopt(impl->sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&reuseaddr), sizeof(int)) == -1)
					throw sockets_error("setsockopt");

				if (setsockopt(impl->sock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&ipv6only), sizeof(int)) == -1)
					throw sockets_error("setsockopt");

				if (::bind(impl->sock, reinterpret_cast<sockaddr*>(&myaddr), sizeof(myaddr)) == -1)
					throw sockets_error("bind");

				if (listen(impl->sock, impl->backlog) == -1)
					throw sockets_error("listen");
#endif

				while (true) {
					struct sockaddr_in6 their_addr;
#ifdef _WIN32
					SOCKET newsock;
					int size = sizeof(their_addr);
#else
					int newsock;
					socklen_t size = sizeof(their_addr);
#endif

					newsock = accept(impl->sock, reinterpret_cast<sockaddr*>(&their_addr), &size);

#ifdef _WIN32
					if (newsock != INVALID_SOCKET) {
#else
					if (newsock != -1) {
#endif
						unique_lock<shared_timed_mutex> guard(impl->vector_mutex);

						impl->client_threads.emplace_back(newsock, *this, impl->msg_handler, impl->conn_handler);
					} else
						throw sockets_error("accept");
				}
			} catch (...) {
#ifdef _WIN32
				closesocket(impl->sock);
#else
				::close(impl->sock);
#endif
				throw;
			}

#ifdef _WIN32
			closesocket(impl->sock);
#else
			::close(impl->sock);
#endif
		} catch (...) {
#ifdef _WIN32
			WSACleanup();
#endif
			throw;
		}

#ifdef _WIN32
		WSACleanup();
#endif
	}

	void server::for_each(function<void(client_thread&)> func) {
		std::shared_lock<std::shared_timed_mutex> guard(impl->vector_mutex);

		for (auto& ct : impl->client_threads) {
			func(ct);
		}
	}

	void server::close() {
#ifdef _WIN32
		if (impl->sock != INVALID_SOCKET)
			closesocket(impl->sock);
#else
		if (impl->sock != -1)
			::close(impl->sock);
#endif
	}

	server::server(uint16_t port, int backlog, const std::function<void(client_thread&, const std::string&)>& msg_handler,
			   const std::function<void(client_thread&)>& conn_handler) {
		impl = new server_pimpl(port, backlog, msg_handler, conn_handler);
	}

	server::~server() {
		delete impl;
	}
}
