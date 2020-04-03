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

#include "wscpp.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#endif
#include <string.h>
#include <random>
#include <map>
#include "wsclient-impl.h"
#include "b64.h"
#include "sha1.h"

using namespace std;

#define MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

namespace ws {
	client::client(const string& host, uint16_t port, const string& path, const function<void(client&, const string&)>& msg_handler) {
		impl = new client_pimpl(*this, host, port, path, msg_handler);
	}

	client_pimpl::client_pimpl(client& parent, const std::string& host, uint16_t port, const std::string& path, const std::function<void(client&, const std::string&)>& msg_handler) :
			parent(parent),
			host(host),
			port(port),
			path(path),
			msg_handler(msg_handler) {
#ifdef _WIN32
		WSADATA wsa_data;

		if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
			throw runtime_error("WSAStartup failed.");
#endif

		try {
			int wsa_error = 0;

			{
				struct addrinfo hints, *result;

				memset(&hints, 0, sizeof(hints));
				hints.ai_family = AF_UNSPEC;
				hints.ai_socktype = SOCK_STREAM;
				hints.ai_protocol = IPPROTO_TCP;

				if (getaddrinfo(host.c_str(), to_string(port).c_str(), &hints, &result) != 0)
					throw runtime_error("getaddr failed.");

				try {
					for (struct addrinfo* ai = result; ai; ai = ai->ai_next) {
						sock = socket(ai->ai_family, SOCK_STREAM, ai->ai_protocol);
#ifdef _WIN32
						if (sock == INVALID_SOCKET)
							throw runtime_error("socket failed (error " + to_string(WSAGetLastError()) + ")");
#else
						if (sock == -1)
							throw runtime_error("socket failed (error " + to_string(errno) + ")");
#endif

#ifdef _WIN32
						if (connect(sock, ai->ai_addr, (int)ai->ai_addrlen) == SOCKET_ERROR) {
							wsa_error = WSAGetLastError();
							closesocket(sock);
							sock = INVALID_SOCKET;
#else
						if (connect(sock, ai->ai_addr, (int)ai->ai_addrlen) == -1) {
							wsa_error = errno;
							close(sock);
							sock = -1;
#endif
							continue;
						}

						break;
					}
				} catch (...) {
					freeaddrinfo(result);
					throw;
				}

				freeaddrinfo(result);
			}

#ifdef _WIN32
			if (sock == INVALID_SOCKET)
#else
			if (sock == -1)
#endif
				throw runtime_error("Could not connect to " + host + " (error " + to_string(wsa_error) + ").");

			open = true;

			send_handshake();

			t = new thread([&]() {
				try {
					recv_thread();
				} catch (...) {
				}

				open = false;
			});
		} catch (...) {
#ifdef _WIN32
			WSACleanup();
#endif
			throw;
		}
	}

	client::~client() {
		delete impl;
	}

	client_pimpl::~client_pimpl() {
#ifdef _WIN32
		if (shutdown(sock, SD_SEND) != SOCKET_ERROR) {
#else
		if (shutdown(sock, SHUT_WR) != -1) {
#endif
			char buf[4096];

			while (::recv(sock, buf, sizeof(buf), 0) > 0) {
			}

#ifdef _WIN32
			closesocket(sock);
#else
			close(sock);
#endif
		}

		if (t) {
			try {
				t->join();
			} catch (...) {
			}

			delete t;
		}

#ifdef _WIN32
		WSACleanup();
#endif
	}

	string client_pimpl::random_key() {
		mt19937 rng;
		rng.seed(random_device()());
		uniform_int_distribution<mt19937::result_type> dist(0, 0xffffffff);
		uint32_t rand[4];

		for (unsigned int i = 0; i < 4; i++) {
			rand[i] = dist(rng);
		}

		return b64encode(string((char*)rand, 16));
	}

	void client_pimpl::send_raw(const string_view& s) const {
#ifdef _WIN32
		if (::send(sock, s.data(), (int)s.length(), 0) == SOCKET_ERROR)
			throw runtime_error("send failed (error " + to_string(WSAGetLastError()) + ")");
#else
		if (::send(sock, s.data(), (int)s.length(), 0) == -1)
			throw runtime_error("send failed (error " + to_string(errno) + ")");
#endif
	}

	string client_pimpl::recv_http() {
		string buf;

		do {
			char s[4096];
			int bytes = ::recv(sock, s, sizeof(s), MSG_PEEK);

#ifdef _WIN32
			if (bytes == SOCKET_ERROR)
#else
			if (bytes == -1)
#endif
				throw runtime_error("recv 1 failed.");
			else if (bytes == 0) {
				open = false;
				return "";
			}

			buf += string(s, bytes);

			size_t endmsg = string(s, bytes).find("\r\n\r\n");

			if (endmsg != string::npos) {
				int ret;

				ret = ::recv(sock, s, (int)(endmsg + 4), MSG_WAITALL);

#ifdef _WIN32
				if (ret == SOCKET_ERROR)
#else
				if (ret == -1)
#endif
					throw runtime_error("recv 2 failed.");
				else if (ret == 0) {
					open = false;
					return "";
				}

				return buf.substr(0, buf.find("\r\n\r\n") + 4);
			} else {
				int ret = ::recv(sock, s, bytes, MSG_WAITALL);

#ifdef _WIN32
				if (ret == SOCKET_ERROR)
#else
				if (ret == -1)
#endif
					throw runtime_error("recv 4 failed.");
				else if (ret == 0) {
					open = false;
					return "";
				}
			}
		} while (true);
	}

	void client_pimpl::send_handshake() {
		string key = random_key();

		send_raw("GET "s + path + " HTTP/1.1\r\nHost: "s + host + ":"s + to_string(port) + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "s + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"s);

		string mess = recv_http();

		if (!open)
			throw runtime_error("Socket closed unexpectedly.");

		bool first = true;
		size_t nl = mess.find("\r\n"), nl2 = 0;
		string verb;
		map<string, string> headers;
		unsigned int status = 0;

		do {
			if (first) {
				size_t space = mess.find(" ");

				if (space != string::npos && space <= nl) {
					size_t space2 = mess.find(" ", space + 1);
					string ss;

					if (space2 == string::npos || space2 > nl)
						ss = mess.substr(space + 1, nl - space - 1);
					else
						ss = mess.substr(space + 1, space2 - space - 1);

					try {
						status = stoul(ss);
					} catch (...) {
						throw runtime_error("Error calling stoul on \"" + ss + "\"");
					}
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

		if (status != 101)
			throw runtime_error("Server returned HTTP status " + to_string(status) + ", expected 101.");

		if (headers.count("Upgrade") == 0 || headers.count("Connection") == 0 || headers.count("Sec-WebSocket-Accept") == 0 || headers.at("Upgrade") != "websocket" || headers.at("Connection") != "Upgrade")
			throw runtime_error("Malformed response.");

		if (headers.at("Sec-WebSocket-Accept") != b64encode(sha1(key + MAGIC_STRING)))
			throw runtime_error("Invalid value for Sec-WebSocket-Accept.");
	}

	void client::send_ws_message(enum opcode opcode, const string_view& payload) const {
		string header;
		uint64_t len = payload.length();

		header.resize(6);
		header[0] = 0x80 | ((uint8_t)opcode & 0xf);

		if (len <= 125) {
			header[1] = 0x80 | (uint8_t)len;
			memset(&header[2], 0, 4);
		} else if (len < 0x10000) {
			header.resize(8);
			header[1] = (uint8_t)0xfe;
			header[2] = (len & 0xff00) >> 8;
			header[3] = len & 0xff;
			memset(&header[4], 0, 4);
		} else {
			header.resize(14);
			header[1] = (uint8_t)0xff;
			header[2] = (uint8_t)((len & 0xff00000000000000) >> 56);
			header[3] = (uint8_t)((len & 0xff000000000000) >> 48);
			header[4] = (uint8_t)((len & 0xff0000000000) >> 40);
			header[5] = (uint8_t)((len & 0xff00000000) >> 32);
			header[6] = (uint8_t)((len & 0xff000000) >> 24);
			header[7] = (uint8_t)((len & 0xff0000) >> 16);
			header[8] = (uint8_t)((len & 0xff00) >> 8);
			header[9] = (uint8_t)(len & 0xff);
			memset(&header[10], 0, 4);
		}

		impl->send_raw(header);
		impl->send_raw(payload);
	}

	string client_pimpl::recv(unsigned int len) {
		char s[4096];
		int bytes, err = 0;

		if (len == 0)
			len = sizeof(s);

		do {
			bytes = ::recv(sock, s, len, 0);

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

	void client_pimpl::parse_ws_message(enum opcode opcode, const string& payload) {
		switch (opcode) {
			case opcode::close:
				open = false;
				return;

			case opcode::ping:
				parent.send_ws_message(opcode::pong, payload);
				break;

			case opcode::text: {
				if (msg_handler)
					msg_handler(parent, payload);

				break;
			}

			default:
				break;
		}
	}

	void client_pimpl::recv_thread() {
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

	void client::join() const {
		if (impl->t)
			impl->t->join();
	}

	bool client::is_open() const {
		return impl->open;
	}
}
