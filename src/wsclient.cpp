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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include "wscpp.h"
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <gssapi/gssapi.h>
#endif
#include <string.h>
#include <random>
#include <map>
#include <stdexcept>
#include <charconv>
#include "wsclient-impl.h"
#include "b64.h"
#include "sha1.h"
#include "wsexcept.h"

using namespace std;

#define MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

namespace ws {
	client::client(const string& host, uint16_t port, const string& path,
				   const client_msg_handler& msg_handler, const client_disconn_handler& disconn_handler,
				   bool enc) {
		impl = new client_pimpl(*this, host, port, path, msg_handler, disconn_handler, enc);
	}

	void client_pimpl::open_connexion() {
		int wsa_error = 0;

		struct addrinfo hints, *result;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		if (getaddrinfo(host.c_str(), to_string(port).c_str(), &hints, &result) != 0)
			throw formatted_error("getaddr failed.");

		try {
			for (struct addrinfo* ai = result; ai; ai = ai->ai_next) {
				char hostname[NI_MAXHOST];

				sock = socket(ai->ai_family, SOCK_STREAM, ai->ai_protocol);
				if (sock == INVALID_SOCKET) {
#ifdef _WIN32
					throw formatted_error("socket failed (error {})", wsa_error_to_string(WSAGetLastError()));
#else
					throw formatted_error("socket failed (error {})", errno_to_string(errno));
#endif
				}

#ifdef _WIN32
				if (connect(sock, ai->ai_addr, (int)ai->ai_addrlen) == SOCKET_ERROR) {
					wsa_error = WSAGetLastError();
					closesocket(sock);
					sock = INVALID_SOCKET;
					continue;
				}
#else
				if (connect(sock, ai->ai_addr, (int)ai->ai_addrlen) == -1) {
					wsa_error = errno;
					close(sock);
					sock = INVALID_SOCKET;
					continue;
				}
#endif

				// FIXME - only do this if necessary?
				if (getnameinfo(ai->ai_addr, ai->ai_addrlen, hostname, NI_MAXHOST, nullptr, 0, 0) == 0)
					fqdn = hostname;

				break;
			}
		} catch (...) {
			freeaddrinfo(result);
			throw;
		}

		freeaddrinfo(result);

		if (sock == INVALID_SOCKET) {
#ifdef _WIN32
			throw formatted_error("Could not connect to {} (error {}).", host, wsa_error_to_string(wsa_error));
#else
			throw formatted_error("Could not connect to {} (error {}).", host, errno_to_string(wsa_error));
#endif
		}

		open = true;
	}

	client_pimpl::client_pimpl(client& parent, const std::string& host, uint16_t port, const std::string& path,
							   const client_msg_handler& msg_handler, const client_disconn_handler& disconn_handler,
							   bool enc) :
			parent(parent),
			host(host),
			port(port),
			path(path),
			msg_handler(msg_handler),
			disconn_handler(disconn_handler) {
#ifdef _WIN32
		WSADATA wsa_data;

		if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
			throw formatted_error("WSAStartup failed.");

		try {
#endif
			open_connexion();

			if (enc)
				ssl.reset(new client_ssl(*this));

			send_handshake();

			t = new thread([&]() {
				exception_ptr except;

				try {
					recv_thread();
				} catch (...) {
					except = current_exception();
				}

				open = false;

				if (this->disconn_handler)
					this->disconn_handler(parent, except);
			});
#ifdef _WIN32
		} catch (...) {
			WSACleanup();
			throw;
		}
#endif
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

#ifdef _WIN32
		if (SecIsValidHandle(&cred_handle))
			FreeCredentialsHandle(&cred_handle);

		if (ctx_handle_set)
			DeleteSecurityContext(&ctx_handle);
#endif

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

	void client_pimpl::set_send_timeout(unsigned int timeout) const {
#ifdef _WIN32
		DWORD tv = timeout * 1000;

		if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv)) != 0)
			throw formatted_error("setsockopt returned {}.", wsa_error_to_string(WSAGetLastError()));
#else
		struct timeval tv;
		tv.tv_sec = timeout;
		tv.tv_usec = 0;

		if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv)) != 0)
			throw formatted_error("setsockopt returned {}.", errno_to_string(errno));
#endif
	}

	void client_pimpl::send_raw(const string_view& s, unsigned int timeout) const {
		if (timeout != 0)
			set_send_timeout(timeout);

		try {
			auto ret = ::send(sock, s.data(), (int)s.length(), 0);

#ifdef _WIN32
			if (ret == SOCKET_ERROR)
				throw formatted_error("send failed (error {})", wsa_error_to_string(WSAGetLastError()));
#else
			if (ret == -1)
				throw formatted_error("send failed (error {})", errno_to_string(errno));
#endif

			if ((size_t)ret < s.length())
				throw formatted_error("send sent {} bytes, expected {}", ret, s.length());
		} catch (...) {
			if (timeout != 0)
				set_send_timeout(0);

			throw;
		}

		if (timeout != 0)
			set_send_timeout(0);
	}

	string client_pimpl::recv_http() {
		do {
			auto pos = recvbuf.find("\r\n\r\n");

			if (pos != string::npos) {
				auto ret = recvbuf.substr(0, pos + 4);

				recvbuf = recvbuf.substr(pos + 4);

				return ret;
			}

			char s[4096];
			int bytes;

			if (ssl) {
				bytes = ssl->recv(sizeof(s), s);

				if (!open)
					return "";
			} else {
				bytes = ::recv(sock, s, sizeof(s), 0);

#ifdef _WIN32
				if (bytes == SOCKET_ERROR)
					throw formatted_error("recv failed ({}).", wsa_error_to_string(WSAGetLastError()));
#else
				if (bytes == -1)
					throw formatted_error("recv failed ({}).", errno_to_string(errno));
#endif

				if (bytes == 0) {
					open = false;
					return "";
				}
			}

			recvbuf += string(s, bytes);
		} while (true);
	}

#ifdef _WIN32
	static __inline u16string utf8_to_utf16(const string_view& s) {
		u16string ret;

		if (s.empty())
			return u"";

		auto len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.length(), nullptr, 0);

		if (len == 0)
			throw formatted_error("MultiByteToWideChar 1 failed.");

		ret.resize(len);

		len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.length(), (wchar_t*)ret.data(), len);

		if (len == 0)
			throw formatted_error("MultiByteToWideChar 2 failed.");

		return ret;
	}

	void client_pimpl::send_auth_response(const string_view& auth_type, const string_view& auth_msg, const string& req) {
		SECURITY_STATUS sec_status;
		TimeStamp timestamp;
		SecBuffer inbufs[2], outbuf;
		SecBufferDesc in, out;
		unsigned long context_attr;
		u16string auth_typew = utf8_to_utf16(auth_type);
		u16string spn;

		if (auth_type == "Negotiate" && fqdn.empty())
			throw formatted_error("Cannot do Negotiate authentication as FQDN not found.");

		if (!SecIsValidHandle(&cred_handle)) {
			sec_status = AcquireCredentialsHandleW(nullptr, (SEC_WCHAR*)auth_typew.c_str(), SECPKG_CRED_OUTBOUND, nullptr,
												   nullptr, nullptr, nullptr, &cred_handle, &timestamp);
			if (FAILED(sec_status))
				throw formatted_error("AcquireCredentialsHandle returned {}", (enum sec_error)sec_status);
		}

		auto auth = b64decode(auth_msg);

		if (!auth_msg.empty()) {
			inbufs[0].cbBuffer = auth.length();
			inbufs[0].BufferType = SECBUFFER_TOKEN;
			inbufs[0].pvBuffer = auth.data();

			inbufs[1].cbBuffer = 0;
			inbufs[1].BufferType = SECBUFFER_EMPTY;
			inbufs[1].pvBuffer = nullptr;

			in.ulVersion = SECBUFFER_VERSION;
			in.cBuffers = 2;
			in.pBuffers = inbufs;
		}

		outbuf.cbBuffer = 0;
		outbuf.BufferType = SECBUFFER_TOKEN;
		outbuf.pvBuffer = nullptr;

		out.ulVersion = SECBUFFER_VERSION;
		out.cBuffers = 1;
		out.pBuffers = &outbuf;

		if (auth_type == "Negotiate")
			spn = u"HTTP/" + utf8_to_utf16(fqdn);

		sec_status = InitializeSecurityContextW(&cred_handle, ctx_handle_set ? &ctx_handle : nullptr,
												auth_type == "Negotiate" ? (SEC_WCHAR*)spn.c_str() : nullptr,
												ISC_REQ_ALLOCATE_MEMORY, 0, SECURITY_NATIVE_DREP, auth_msg.empty() ? nullptr : &in, 0,
												&ctx_handle, &out, &context_attr, &timestamp);
		if (FAILED(sec_status))
			throw formatted_error("InitializeSecurityContext returned {}", (enum sec_error)sec_status);

		auto sspi = string((char*)outbuf.pvBuffer, outbuf.cbBuffer);

		if (outbuf.pvBuffer)
			FreeContextBuffer(outbuf.pvBuffer);

		ctx_handle_set = true;

		if (sec_status == SEC_I_CONTINUE_NEEDED || sec_status == SEC_I_COMPLETE_AND_CONTINUE ||
			sec_status == SEC_E_OK) {
			auto b64 = b64encode(sspi);
			auto msg = req + "Authorization: " + string(auth_type) + " " + b64 + "\r\n\r\n";

			if (ssl)
				ssl->send(msg);
			else
				send_raw(msg);
		}

		// FIXME - SEC_I_COMPLETE_NEEDED (and SEC_I_COMPLETE_AND_CONTINUE)?
	}
#else
	void client_pimpl::send_auth_response(const string_view& auth_type, const string_view& auth_msg, const string& req) {
		OM_uint32 major_status, minor_status;
		gss_buffer_desc recv_tok, send_tok, name_buf;
		gss_name_t gss_name;
		string outbuf;

		if (auth_type == "Negotiate" && fqdn.empty())
			throw formatted_error("Cannot do Negotiate authentication as FQDN not found.");

		if (cred_handle != 0) {
			major_status = gss_acquire_cred(&minor_status, GSS_C_NO_NAME/*FIXME?*/, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
											GSS_C_INITIATE, &cred_handle, nullptr, nullptr);

			if (major_status != GSS_S_COMPLETE)
				throw gss_error("gss_acquire_cred", major_status, minor_status);
		}

		auto auth = b64decode(auth_msg);

		recv_tok.length = auth.length();
		recv_tok.value = auth.data();

		string spn = "HTTP/" + fqdn;

		name_buf.length = spn.length();
		name_buf.value = (void*)spn.data();

		major_status = gss_import_name(&minor_status, &name_buf, GSS_C_NO_OID, &gss_name);
		if (major_status != GSS_S_COMPLETE)
			throw gss_error("gss_import_name", major_status, minor_status);

		major_status = gss_init_sec_context(&minor_status, cred_handle, &ctx_handle, gss_name, GSS_C_NO_OID,
											GSS_C_DELEG_FLAG, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
											&recv_tok, nullptr, &send_tok, nullptr, nullptr);

		if (major_status != GSS_S_CONTINUE_NEEDED && major_status != GSS_S_COMPLETE)
			throw gss_error("gss_init_sec_context", major_status, minor_status);

		if (send_tok.length != 0) {
			outbuf = string((char*)send_tok.value, send_tok.length);

			gss_release_buffer(&minor_status, &send_tok);
		}

		if (!outbuf.empty()) {
			auto b64 = b64encode(outbuf);
			auto msg = req + "Authorization: " + string(auth_type) + " " + b64 + "\r\n\r\n";

			if (ssl)
				ssl->send(msg);
			else
				send_raw(msg);

			return;
		}
	}
#endif

	void client_pimpl::send_handshake() {
		bool again;
		string key = random_key();
		string req = "GET "s + path + " HTTP/1.1\r\n"
					 "Host: "s + host + ":"s + to_string(port) + "\r\n"
					 "Upgrade: websocket\r\n"
					 "Connection: Upgrade\r\n"
					 "Sec-WebSocket-Key: "s + key + "\r\n"
					 "Sec-WebSocket-Version: 13\r\n";

		if (ssl)
			ssl->send(req + "\r\n"s);
		else
			send_raw(req + "\r\n"s);

		do {
			string mess = recv_http();

			if (!open)
				throw formatted_error("Socket closed unexpectedly.");

			again = false;

			bool first = true;
			size_t nl = mess.find("\r\n"), nl2 = 0;
			map<string, string> headers;
			unsigned int status = 0;

			do {
				if (first) {
					size_t space = mess.find(" ");

					if (space != string::npos && space <= nl) {
						size_t space2 = mess.find(" ", space + 1);
						string_view sv;

						if (space2 == string::npos || space2 > nl)
							sv = string_view{mess}.substr(space + 1, nl - space - 1);
						else
							sv = string_view{mess}.substr(space + 1, space2 - space - 1);

						auto [ptr, ec] = from_chars(sv.data(), sv.data() + sv.length(), status);

						if (ptr != sv.data() + sv.length())
							throw formatted_error("Server returned invalid HTTP status \"{}\"", sv);
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

			if (status == 401 && headers.count("WWW-Authenticate") != 0) {
				const auto& h = headers.at("WWW-Authenticate");
				auto st = h.find(" ");
				string_view auth_type, auth_msg;

				if (st == string::npos)
					auth_type = h;
				else {
					auth_type = string_view(h).substr(0, st);
					auth_msg = string_view(h).substr(st + 1);
				}

#ifdef _WIN32
				if (auth_type == "NTLM" || auth_type == "Negotiate")
					send_auth_response(auth_type, auth_msg, req);
#else
				if (auth_type == "Negotiate")
					send_auth_response(auth_type, auth_msg, req);
#endif

				again = true;
				continue;
			}

			if (status != 101)
				throw formatted_error("Server returned HTTP status {}, expected 101.", status);

			if (headers.count("Upgrade") == 0 || headers.count("Connection") == 0 || headers.count("Sec-WebSocket-Accept") == 0 || headers.at("Upgrade") != "websocket" || headers.at("Connection") != "Upgrade")
				throw formatted_error("Malformed response.");

			if (headers.at("Sec-WebSocket-Accept") != b64encode(sha1(key + MAGIC_STRING)))
				throw formatted_error("Invalid value for Sec-WebSocket-Accept.");
		} while (again);
	}

	void client::send(const string_view& payload, enum opcode opcode, unsigned int timeout) const {
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

		if (impl->ssl) { // FIXME - timeout
			impl->ssl->send(header);
			impl->ssl->send(payload);
		} else {
			impl->send_raw(header, timeout);
			impl->send_raw(payload, timeout);
		}
	}

	void client_pimpl::recv(unsigned int len, void* data) {
		int bytes, err = 0;
		unsigned int left;
		char* buf;

		if (len == 0)
			return;

		left = len;
		buf = (char*)data;

		if (!recvbuf.empty()) {
			auto to_copy = min(left, (unsigned int)recvbuf.length());

			memcpy(buf, recvbuf.data(), to_copy);
			recvbuf = recvbuf.substr(to_copy);

			if (left == to_copy)
				return;

			left -= to_copy;
			buf += to_copy;
		}

		do {
			if (ssl) {
				bytes = ssl->recv(left, buf);

				if (open)
					return;
			} else {
				bytes = ::recv(sock, buf, left, 0);

#ifdef _WIN32
				if (bytes == SOCKET_ERROR) {
					err = WSAGetLastError();
					break;
				}
#else
				if (bytes == -1) {
					err = errno;
					break;
				}
#endif

				if (bytes == 0) {
					open = false;
					return;
				}

				buf += bytes;
				left -= bytes;
			}
		} while (left > 0);

		if (ssl) {
#ifdef _WIN32
			if (bytes == SOCKET_ERROR) {
				if (err == WSAECONNRESET) {
					open = false;
					return;
				}

				throw formatted_error("recv failed ({}).", wsa_error_to_string(err));
			}
#else
			if (bytes == -1) {
				if (err == ECONNRESET) {
					open = false;
					return;
				}

				throw formatted_error("recv failed ({}).", errno_to_string(err));
			}
#endif
		}
	}

	void client_pimpl::parse_ws_message(enum opcode opcode, const string& payload) {
		switch (opcode) {
			case opcode::close:
				open = false;
				return;

			case opcode::ping:
				parent.send(payload, opcode::pong);
				break;

			default:
				break;
		}

		if (msg_handler)
			msg_handler(parent, payload, opcode);
	}

	void client_pimpl::recv_thread() {
		string payloadbuf;

		while (open) {
			header h;

			recv(sizeof(header), &h);

			if (!open)
				break;

			auto len = (uint64_t)h.len;

			if (len == 126) {
				uint16_t extlen;

				recv(sizeof(extlen), &extlen);

				if (!open)
					break;

#ifdef _MSC_VER
				len = _byteswap_ushort(extlen);
#else
				len = __builtin_bswap16(extlen);
#endif
			} else if (len == 127) {
				uint64_t extlen;

				recv(sizeof(extlen), &extlen);

				if (!open)
					break;

#ifdef _MSC_VER
				len = _byteswap_uint64(extlen);
#else
				len = __builtin_bswap64(extlen);
#endif
			}

			char mask_key[4];

			if (h.mask) {
				recv(sizeof(mask_key), mask_key);

				if (!open)
					break;
			}

			string payload;

			if (len > 0) {
				payload.resize(len);
				recv(payload.length(), payload.data());
			}

			if (!open)
				break;

			if (h.mask) {
				// FIXME - speed this up by treating mask_key as uint32_t?
				for (unsigned int i = 0; i < payload.length(); i++) {
					payload[i] ^= mask_key[i % 4];
				}
			}

			if (!h.fin) {
				if (h.opcode != opcode::invalid)
					last_opcode = h.opcode;

				payloadbuf += payload;
			} else if (!payloadbuf.empty()) {
				parse_ws_message(last_opcode, payloadbuf + payload);
				payloadbuf.clear();
			} else
				parse_ws_message(h.opcode, payload);
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
