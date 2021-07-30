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
#include <map>
#include <mutex>
#include <iostream>
#include <charconv>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <limits.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#else
#include <ws2tcpip.h>
#include <ntdsapi.h>
#endif
#include "wscpp.h"
#include <fcntl.h>
#include <string.h>
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
	server_client_pimpl::~server_client_pimpl() {
#ifdef _WIN32
		if ((int)fd != SOCKET_ERROR)
			closesocket(fd);
#else
		if (fd != -1)
			close(fd);
#endif

#ifdef _WIN32
		if (SecIsValidHandle(&cred_handle))
			FreeCredentialsHandle(&cred_handle);

		if (ctx_handle_set)
			DeleteSecurityContext(&ctx_handle);
#endif
	}

	server_client::~server_client() {
		delete impl;
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
#endif

	void server_client_pimpl::read() {
		auto msg = recv();

		if (!open)
			return;

		recvbuf += move(msg);

		if (state == state_enum::http)
			process_http_messages();

		if (state != state_enum::websocket)
			return;

		while (true) {
			if (recvbuf.length() < 2)
				return;

			bool fin = (recvbuf[0] & 0x80) != 0;
			auto opcode = (enum opcode)(uint8_t)(recvbuf[0] & 0xf);
			bool mask = (recvbuf[1] & 0x80) != 0;
			uint64_t len = recvbuf[1] & 0x7f;

			auto sv = string_view(recvbuf).substr(2);

			if (len == 126) {
				if (sv.length() < 2)
					return;

				len = ((uint8_t)sv[0] << 8) | (uint8_t)sv[1];
				sv = sv.substr(2);
			} else if (len == 127) {
				if (sv.length() < 8)
					return;

				len = (uint8_t)sv[0];
				len <<= 8;
				len |= (uint8_t)sv[1];
				len <<= 8;
				len |= (uint8_t)sv[2];
				len <<= 8;
				len |= (uint8_t)sv[3];
				len <<= 8;
				len |= (uint8_t)sv[4];
				len <<= 8;
				len |= (uint8_t)sv[5];
				len <<= 8;
				len |= (uint8_t)sv[6];
				len <<= 8;
				len |= (uint8_t)sv[7];

				sv = sv.substr(8);
			}

			string_view mask_key;

			if (mask) {
				if (sv.length() < 4)
					return;

				mask_key = sv.substr(0, 4);
				sv = sv.substr(4);
			}

			if (sv.length() < len)
				return;

			if (mask && len != 0) {
				span<char> payload((char*)&sv[0], len);

				for (unsigned int i = 0; i < payload.size(); i++) {
					payload[i] ^= mask_key[i % 4];
				}
			}

			if (!fin) {
				if (opcode != opcode::invalid)
					last_opcode = opcode;

				payloadbuf += sv.substr(0, len);
			} else if (!payloadbuf.empty()) {
				payloadbuf += sv.substr(0, len);

				parse_ws_message(last_opcode, payloadbuf);
				payloadbuf.clear();
			} else
				parse_ws_message(opcode, sv.substr(0, len));

			sv = sv.substr(len);
			recvbuf = recvbuf.substr(sv.data() - recvbuf.data());
		}
	}

	void server_client::send(const string_view& payload, enum opcode opcode) const {
		size_t len = payload.length();

		if (len <= 125) {
			char msg[2];

			msg[0] = 0x80 | ((uint8_t)opcode & 0xf);
			msg[1] = (char)len;

			impl->send_raw(string_view(msg, 2));
		} else if (len < 0x10000) {
			char msg[4];

			msg[0] = 0x80 | ((uint8_t)opcode & 0xf);
			msg[1] = 126;
			msg[2] = (len & 0xff00) >> 8;
			msg[3] = len & 0xff;

			impl->send_raw(string_view(msg, 4));
		} else {
			char msg[10];

			msg[0] = 0x80 | ((uint8_t)opcode & 0xf);
			msg[1] = 127;
			msg[2] = (char)((len & 0xff00000000000000) >> 56);
			msg[3] = (char)((len & 0xff000000000000) >> 48);
			msg[4] = (char)((len & 0xff0000000000) >> 40);
			msg[5] = (char)((len & 0xff00000000) >> 32);
			msg[6] = (char)((len & 0xff000000) >> 24);
			msg[7] = (char)((len & 0xff0000) >> 16);
			msg[8] = (char)((len & 0xff00) >> 8);
			msg[9] = len & 0xff;

			impl->send_raw(string_view(msg, 10));
		}

		impl->send_raw(payload);
	}

	void server_client_pimpl::send_raw(string_view sv) {
		if (!sendbuf.empty()) {
			sendbuf.append(sv);
#ifdef _WIN32
			serv.impl->ev.set();
#endif
			return;
		}

		do {
			int bytes = send(fd, sv.data(), (int)sv.length(), 0);

#ifdef _WIN32
			if (bytes == SOCKET_ERROR) {
				if (WSAGetLastError() == WSAEWOULDBLOCK) {
					sendbuf.append(sv);
					serv.impl->ev.set();
					return;
				} else
					throw formatted_error("send failed ({}).", wsa_error_to_string(WSAGetLastError()));
			}
#else
			if (bytes == -1) {
				if (errno == EWOULDBLOCK) {
					sendbuf.append(sv);
					return;
				} else
					throw formatted_error("send failed ({}).", errno_to_string(errno));
			}
#endif

			if ((size_t)bytes == sv.length())
				break;

			sv = sv.substr(bytes);
		} while (true);
	}

#ifdef _WIN32
	static __inline string utf16_to_utf8(const u16string_view& s) {
		string ret;

		if (s.empty())
			return "";

		auto len = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)s.data(), (int)s.length(), nullptr, 0,
									nullptr, nullptr);

		if (len == 0)
			throw formatted_error("WideCharToMultiByte 1 failed.");

		ret.resize(len);

		len = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)s.data(), (int)s.length(), ret.data(), len,
								nullptr, nullptr);

		if (len == 0)
			throw formatted_error("WideCharToMultiByte 2 failed.");

		return ret;
	}

	void server_client_pimpl::get_username(HANDLE token) {
		vector<uint8_t> buf;
		TOKEN_USER* tu;
		DWORD ret = 0;
		WCHAR usernamew[256], domain_namew[256];
		DWORD user_size, domain_size;
		SID_NAME_USE use;

		buf.resize(sizeof(TOKEN_USER));
		tu = (TOKEN_USER*)&buf[0];

		if (GetTokenInformation(token, TokenUser, tu, buf.size(), &ret) == 0) {
			auto le = GetLastError();

			if (le != ERROR_INSUFFICIENT_BUFFER)
				throw formatted_error("GetTokenInformation failed (last error {})", le);
		}

		buf.resize(ret);
		tu = (TOKEN_USER*)&buf[0];

		if (GetTokenInformation(token, TokenUser, tu, buf.size(), &ret) == 0)
			throw formatted_error("GetTokenInformation failed (last error {})", GetLastError());

		if (!IsValidSid(tu->User.Sid))
			throw formatted_error("Invalid SID.");

		user_size = sizeof(usernamew) / sizeof(WCHAR);
		domain_size = sizeof(domain_namew) / sizeof(WCHAR);

		if (!LookupAccountSidW(nullptr, tu->User.Sid, usernamew, &user_size, domain_namew,
							   &domain_size, &use))
			throw formatted_error("LookupAccountSid failed (last error {})", GetLastError());

		username = utf16_to_utf8(u16string_view((char16_t*)usernamew));
		domain_name = utf16_to_utf8(u16string_view((char16_t*)domain_namew));
	}
#endif

#ifndef _WIN32
	static string get_fqdn() {
		struct addrinfo hints, *info;
		int err;
		char hostname[HOST_NAME_MAX + 1];

		hostname[HOST_NAME_MAX] = 0;
		gethostname(hostname, HOST_NAME_MAX);

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_CANONNAME;

		err = getaddrinfo(hostname, nullptr, &hints, &info);
		if (err != 0)
			throw formatted_error("getaddrinfo failed for {} (error {}).", hostname, err);

		if (!info)
			throw formatted_error("Could not get fully-qualified domain name.");

		string ret = info->ai_canonname;

		freeaddrinfo(info);

		return ret;
	}
#endif

	void server_client_pimpl::handle_handshake(const map<string, string>& headers) {
		if (!serv.impl->auth_type.empty()) {
			string auth;
#ifdef _WIN32
			SECURITY_STATUS sec_status;
			SecBuffer inbufs[2], outbuf;
			SecBufferDesc in, out;
			TimeStamp timestamp;
			unsigned long context_attr;
#else
			OM_uint32 major_status, minor_status;
			OM_uint32 ret_flags;
			gss_buffer_desc recv_tok, send_tok, name_buffer;
			gss_OID mech_type;
			gss_name_t src_name;
#endif

			const auto& auth_type = serv.impl->auth_type;

			if (headers.count("Authorization") > 0) {
				const auto& authstr = headers.at("Authorization");

				if (authstr.length() > auth_type.length() && authstr.substr(0, auth_type.length()) == auth_type &&
					authstr[auth_type.length()] == ' ') {
					auth = b64decode(authstr.substr(auth_type.length() + 1));
				}
			}

			if (auth.empty()) {
				send_raw("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: " + auth_type + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
				return;
			}

#ifdef _WIN32
			if (!SecIsValidHandle(&cred_handle)) {
				if (auth_type == "Negotiate") { // FIXME - log error if this fails, rather than throwing exception?
					auto ret = DsServerRegisterSpnW(DS_SPN_ADD_SPN_OP, L"HTTP", nullptr);
					if (FAILED(ret))
						throw formatted_error("DsServerRegisterSpn returned {}", ret);
				}

				sec_status = AcquireCredentialsHandleW(nullptr, (SEC_WCHAR*)utf8_to_utf16(auth_type).c_str(), SECPKG_CRED_INBOUND,
													   nullptr, nullptr, nullptr, nullptr, &cred_handle, &timestamp);
				if (FAILED(sec_status))
					throw formatted_error("AcquireCredentialsHandle returned {}", (enum sec_error)sec_status);
			}
#else
			if (cred_handle == 0) {
				gss_buffer_desc name_buf;
				gss_name_t gss_name;
				string spn = "HTTP/" + get_fqdn();

				name_buf.length = spn.length();
				name_buf.value = (void*)spn.data();

				major_status = gss_import_name(&minor_status, &name_buf, GSS_C_NO_OID, &gss_name);
				if (major_status != GSS_S_COMPLETE)
					throw gss_error("gss_import_name", major_status, minor_status);

				major_status = gss_acquire_cred(&minor_status, gss_name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
												GSS_C_ACCEPT, &cred_handle, nullptr, nullptr);

				if (major_status != GSS_S_COMPLETE)
					throw gss_error("gss_acquire_cred", major_status, minor_status);
			}
#endif

#ifdef _WIN32
			inbufs[0].cbBuffer = auth.length();
			inbufs[0].BufferType = SECBUFFER_TOKEN;
			inbufs[0].pvBuffer = auth.data();

			inbufs[1].cbBuffer = 0;
			inbufs[1].BufferType = SECBUFFER_EMPTY;
			inbufs[1].pvBuffer = nullptr;

			in.ulVersion = SECBUFFER_VERSION;
			in.cBuffers = 2;
			in.pBuffers = inbufs;

			outbuf.cbBuffer = 0;
			outbuf.BufferType = SECBUFFER_TOKEN;
			outbuf.pvBuffer = nullptr;

			out.ulVersion = SECBUFFER_VERSION;
			out.cBuffers = 1;
			out.pBuffers = &outbuf;

			sec_status = AcceptSecurityContext(&cred_handle, ctx_handle_set ? &ctx_handle : nullptr, &in, ASC_REQ_ALLOCATE_MEMORY,
											   SECURITY_NATIVE_DREP, &ctx_handle, &out, &context_attr,
											   &timestamp);

			auto sspi = string((char*)outbuf.pvBuffer, outbuf.cbBuffer);

			if (outbuf.pvBuffer)
				FreeContextBuffer(outbuf.pvBuffer);

			if (sec_status == SEC_E_LOGON_DENIED) {
				static const string msg = "Logon denied.";

				send_raw("HTTP/1.1 401 Unauthorized\r\nContent-Length: " + to_string(msg.length()) + "\r\n\r\n" + msg);
				return;
			} else if (FAILED(sec_status))
				throw formatted_error("AcceptSecurityContext returned {}", (enum sec_error)sec_status);

			ctx_handle_set = true;

			if (sec_status == SEC_I_CONTINUE_NEEDED || sec_status == SEC_I_COMPLETE_AND_CONTINUE) {
				auto b64 = b64encode(sspi);

				send_raw("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nWWW-Authenticate: " + auth_type + " " + b64 + "\r\n\r\n");

				return;
			}

			// FIXME - SEC_I_COMPLETE_NEEDED (and SEC_I_COMPLETE_AND_CONTINUE)

			{
				HANDLE h;

				sec_status = QuerySecurityContextToken(&ctx_handle, &h);

				if (FAILED(sec_status))
					throw formatted_error("QuerySecurityContextToken returned {}", (enum sec_error)sec_status);

				token.reset(h);
			}

			get_username(token.get());
#else
			recv_tok.length = auth.length();
			recv_tok.value = auth.data();

			major_status = gss_accept_sec_context(&minor_status, &ctx_handle, cred_handle, &recv_tok,
												  GSS_C_NO_CHANNEL_BINDINGS, &src_name, &mech_type, &send_tok,
												  &ret_flags, nullptr, nullptr);

			if (major_status != GSS_S_CONTINUE_NEEDED && major_status != GSS_S_COMPLETE)
				throw gss_error("gss_accept_sec_context", major_status, minor_status);

			string outbuf;

			if (send_tok.length != 0) {
				outbuf = string((char*)send_tok.value, send_tok.length);

				gss_release_buffer(&minor_status, &send_tok);
			}

			if (major_status == GSS_S_CONTINUE_NEEDED) {
				auto b64 = b64encode(outbuf);

				send_raw("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nWWW-Authenticate: " + auth_type + " " + b64 + "\r\n\r\n");

				return;
			}

			major_status = gss_display_name(&minor_status, src_name, &name_buffer, nullptr);
			if (major_status != GSS_S_COMPLETE) {
				gss_release_name(&minor_status, &src_name);
				throw gss_error("gss_display_name", major_status, minor_status);
			}

			username = string((char*)name_buffer.value, name_buffer.length);

			gss_release_name(&minor_status, &src_name);
			gss_release_buffer(&minor_status, &name_buffer);

			if (username.find("@") != string::npos) {
				auto st = username.find("@");

				domain_name = username.substr(st + 1);
				username = username.substr(0, st);
			}
#endif
		}

		if (headers.count("Upgrade") == 0 || lower(headers.at("Upgrade")) != "websocket" || headers.count("Sec-WebSocket-Key") == 0 || headers.count("Sec-WebSocket-Version") == 0) {
			send_raw("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
			return;
		}

		const auto& wsv = headers.at("Sec-WebSocket-Version");
		unsigned int version;

		auto [ptr, ec] = from_chars(wsv.data(), wsv.data() + wsv.length(), version);

		if (ptr != wsv.data() + wsv.length())
			throw runtime_error("Invalid Sec-WebSocket-Version value.");

		if (version > 13) {
			send_raw("HTTP/1.1 400 Bad Request\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\n\r\n");
			return;
		}

		string resp = b64encode(sha1(headers.at("Sec-WebSocket-Key") + MAGIC_STRING));

		send_raw("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + resp + "\r\n\r\n");

		state = state_enum::websocket;

		if (conn_handler)
			conn_handler(parent);
	}

	void server_client_pimpl::internal_server_error(const string& s) {
		try {
			send_raw("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: " + to_string(s.size()) + "\r\nConnection: close\r\n\r\n" + s);
		} catch (...) {
		}
	}

	string server_client_pimpl::recv() {
		char s[4096];
		int bytes, err = 0;

		bytes = ::recv(fd, s, sizeof(s), 0);

#ifdef _WIN32
		if (bytes == SOCKET_ERROR)
			err = WSAGetLastError();

		if (bytes == 0 || (bytes == SOCKET_ERROR && err == WSAECONNRESET)) {
			open = false;
			return "";
		} else if (bytes == SOCKET_ERROR)
			throw formatted_error("recv failed ({}).", wsa_error_to_string(err));
#else
		if (bytes == -1)
			err = errno;

		if (bytes == 0 || (bytes == -1 && err == ECONNRESET)) {
			open = false;
			return "";
		} else if (bytes == -1)
			throw formatted_error("recv failed ({}).", errno_to_string(err));
#endif

		return string(s, bytes);
	}

	void server_client_pimpl::process_http_message(const string& mess) {
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
			send_raw("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
		else if (verb != "GET")
			send_raw("HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
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

	void server_client_pimpl::process_http_messages() {
		do {
			size_t dnl = recvbuf.find("\r\n\r\n");

			if (dnl == string::npos)
				return;

			process_http_message(recvbuf.substr(0, dnl + 2));

			recvbuf = recvbuf.substr(dnl + 4);

			if (state != state_enum::http)
				break;
		} while (true);
	}

	void server_client_pimpl::parse_ws_message(enum opcode opcode, const string_view& payload) {
		switch (opcode) {
			case opcode::close:
				open = false;
				return;

			case opcode::ping:
				parent.send(payload, opcode::pong);
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

	void server::start() {
#ifdef _WIN32
		WSADATA wsaData;

		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
			throw formatted_error("WSAStartup failed.");
#endif

		try {
			struct sockaddr_in6 myaddr;

			memset(&myaddr, 0, sizeof(myaddr));
			myaddr.sin6_family = AF_INET6;
			myaddr.sin6_port = htons(impl->port);
			myaddr.sin6_addr = in6addr_any;

			impl->sock = socket(AF_INET6, SOCK_STREAM, 0);

			if (impl->sock == INVALID_SOCKET)
				throw formatted_error("socket failed.");

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

				if (listen(impl->sock, impl->backlog) == SOCKET_ERROR)
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
#ifdef _WIN32
					WSANETWORKEVENTS netev;

					{
						unique_lock guard(impl->vector_mutex);

						impl->ev.reset();

						if (WSAEventSelect(impl->sock, impl->ev, FD_ACCEPT) == SOCKET_ERROR)
							throw formatted_error("WSAEventSelect failed (error {}).", wsa_error_to_string(WSAGetLastError()));

						for (auto& ct : impl->clients) {
							auto& climpl = *ct.impl;

							long events = FD_READ | FD_WRITE | FD_CLOSE;

							if (WSAEventSelect(climpl.fd, impl->ev, events) == SOCKET_ERROR)
								throw formatted_error("WSAEventSelect failed (error {}).", wsa_error_to_string(WSAGetLastError()));
						}
					}

					if (WaitForSingleObject(impl->ev, INFINITE) == WAIT_FAILED)
						throw formatted_error("WaitForSingleObject failed (error {}).", GetLastError());
#else
					vector<struct pollfd> pollfds;

					pollfds.reserve(impl->clients.size() + 1);

					{
						auto& serv_pf = pollfds.emplace_back();

						serv_pf.fd = impl->sock;
						serv_pf.events = POLLIN;
					}

					{
						unique_lock guard(impl->vector_mutex);

						for (auto& ct : impl->clients) {
							auto& impl = *ct.impl;

							auto& pf = pollfds.emplace_back();

							pf.fd = impl.fd;
							pf.events = POLLIN;

							if (!impl.sendbuf.empty())
								pf.events |= POLLOUT;
						}
					}

					// FIXME - what if send buffer fills up between lock release and poll?

					if (poll(&pollfds[0], pollfds.size(), -1) < 0)
						throw sockets_error("poll");
#endif

#ifdef _WIN32
					if (WSAEnumNetworkEvents(impl->sock, impl->ev, &netev))
						throw formatted_error("WSAEnumNetworkEvents failed (error {}).", wsa_error_to_string(WSAGetLastError()));

					if (netev.lNetworkEvents & FD_ACCEPT) {
#else
					if (pollfds[0].revents) {
#endif
						socket_t newsock;
						struct sockaddr_in6 their_addr;
#ifdef _WIN32
						int size = sizeof(their_addr);
#else
						socklen_t size = sizeof(their_addr);
#endif

						newsock = accept(impl->sock, reinterpret_cast<sockaddr*>(&their_addr), &size);

						// FIXME - don't bring down whole server because of one bad socket

#ifdef _WIN32
						u_long mode = 1;

						if (ioctlsocket(newsock, FIONBIO, &mode) != 0)
								throw formatted_error("ioctlsocket failed ({}).", wsa_error_to_string(WSAGetLastError()));
#else
						int flags = fcntl(newsock, F_GETFL, 0);

						if (flags == -1)
							throw runtime_error("fcntl returned -1");

						if (!(flags & O_NONBLOCK)) {
							flags |= O_NONBLOCK;

							if (fcntl(newsock, F_SETFL, flags) != 0)
								throw runtime_error("fcntl failed");
						}
#endif

						if (newsock != INVALID_SOCKET) {
							unique_lock guard(impl->vector_mutex);

							impl->clients.emplace_back(newsock, *this, their_addr.sin6_addr.s6_addr, impl->msg_handler,
													   impl->conn_handler, impl->disconn_handler);
						} else
							throw sockets_error("accept");

						continue;
					}

					{
						unique_lock guard(impl->vector_mutex);

#ifdef _WIN32
						for (auto& ct : impl->clients) {
							if (WSAEnumNetworkEvents(ct.impl->fd, impl->ev, &netev))
								throw formatted_error("WSAEnumNetworkEvents failed (error {}).", wsa_error_to_string(WSAGetLastError()));

							if (!(netev.lNetworkEvents & (FD_READ | FD_CLOSE | FD_WRITE)))
								continue;

							if (netev.lNetworkEvents & (FD_READ | FD_CLOSE)) {
								ct.impl->read();

								if (!ct.impl->open) {
									if (impl->disconn_handler)
										impl->disconn_handler(ct, {}); // FIXME - catch and propagate exceptions

									for (auto it = impl->clients.begin(); it != impl->clients.end(); it++) {
										if (&*it == &ct) {
											impl->clients.erase(it);
											break;
										}
									}
								}
							} else if (netev.lNetworkEvents & FD_WRITE) {
								string to_send = move(ct.impl->sendbuf);

								ct.impl->send_raw(to_send);
							}

							break;
						}
#else
						for (const auto& pf : pollfds) {
							if (!pf.revents)
								continue;

							for (auto& ct : impl->clients) {
								if (ct.impl->fd == pf.fd) {
									if (pf.revents & POLLIN)
										ct.impl->read();
									else if (pf.revents & POLLOUT) {
										string to_send = move(ct.impl->sendbuf);

										ct.impl->send_raw(to_send);
									}

									if (pf.revents & (POLLHUP | POLLERR | POLLNVAL) || !ct.impl->open) {
										if (impl->disconn_handler)
											impl->disconn_handler(ct, {}); // FIXME - catch and propagate exceptions

										for (auto it = impl->clients.begin(); it != impl->clients.end(); it++) {
											if (&*it == &ct) {
												impl->clients.erase(it);
												break;
											}
										}
									}

									break;
								}
							}

							break;
						}
#endif
					}
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

	void server::for_each(function<bool(server_client&)> func) {
		unique_lock guard(impl->vector_mutex);

		for (auto& ct : impl->clients) {
			if (ct.impl->state == server_client_pimpl::state_enum::websocket) {
				if (!func(ct))
					break;
			}
		}
	}

	void server::close() {
		if (impl->sock != INVALID_SOCKET) {
#ifdef _WIN32
			closesocket(impl->sock);
#else
			::close(impl->sock);
#endif
		}
	}

	server::server(uint16_t port, int backlog, const server_msg_handler& msg_handler,
		       const server_conn_handler& conn_handler, const server_disconn_handler& disconn_handler,
			   const string_view& auth_type) {
		impl = new server_pimpl(port, backlog, msg_handler, conn_handler, disconn_handler, auth_type);
	}

	server::~server() {
		delete impl;
	}

	server_client::server_client(socket_t sock, server& serv, const std::span<uint8_t, 16>& ip_addr, const server_msg_handler& msg_handler,
								 const server_conn_handler& conn_handler, const server_disconn_handler& disconn_handler) {
		impl = new server_client_pimpl(*this, sock, serv, ip_addr, msg_handler, conn_handler, disconn_handler);
	}

	string_view server_client::username() const {
		return impl->username;
	}

	string_view server_client::domain_name() const {
		return impl->domain_name;
	}

#ifdef _WIN32
	void server_client_pimpl::impersonate() const {
		SECURITY_STATUS sec_status;

		if (!ctx_handle_set)
			throw formatted_error("ctx_handle not set");

		sec_status = ImpersonateSecurityContext((PCtxtHandle)&ctx_handle);

		if (FAILED(sec_status))
			throw formatted_error("ImpersonateSecurityContext returned {}", (enum sec_error)sec_status);
	}

	void server_client_pimpl::revert() const {
		SECURITY_STATUS sec_status;

		if (!ctx_handle_set)
			throw formatted_error("ctx_handle not set");

		sec_status = RevertSecurityContext((PCtxtHandle)&ctx_handle);

		if (FAILED(sec_status))
			throw formatted_error("RevertSecurityContext returned {}", (enum sec_error)sec_status);
	}

	void server_client::impersonate() const {
		impl->impersonate();
	}

	void server_client::revert() const {
		impl->revert();
	}

	HANDLE server_client_pimpl::impersonation_token() const {
		return token.get();
	}

	HANDLE server_client::impersonation_token() const {
		return impl->impersonation_token();
	}
#endif

	span<uint8_t, 16> server_client::ip_addr() const {
		return impl->ip_addr;
	}

	string server_client::ip_addr_string() const {
		auto ip = ip_addr();

		static const array<uint8_t, 12> ipv4_pref = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

		if (!memcmp(ip.data(), ipv4_pref.data(), ipv4_pref.size()))
			return fmt::format("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
		else {
			char s[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET6, ip.data(), s, sizeof(s));

			return s;
		}
	}
}
