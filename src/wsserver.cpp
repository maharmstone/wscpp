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
#include <shared_mutex>
#include <mutex>
#include <iostream>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <limits.h>
#include <netdb.h>
#include <arpa/inet.h>
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
#include "wsexcept.h"

using namespace std;

#ifdef _WIN32
HRESULT (WINAPI *_SetThreadDescription)(HANDLE hThread, PCWSTR lpThreadDescription);
#endif

#define MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static string lower(string s) {
	for (auto& c : s) {
		if (c >= 'A' && c <= 'Z')
			c += 'a' - 'A';
	}

	return s;
}

namespace ws {
	client_thread_pimpl::~client_thread_pimpl() {
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

		t.join();
	}

	client_thread::~client_thread() {
		delete impl;
	}

#ifdef _WIN32
	static __inline u16string utf8_to_utf16(const string_view& s) {
		u16string ret;

		if (s.empty())
			return u"";

		auto len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.length(), nullptr, 0);

		if (len == 0)
			throw formatted_error(FMT_STRING("MultiByteToWideChar 1 failed."));

		ret.resize(len);

		len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.length(), (wchar_t*)ret.data(), len);

		if (len == 0)
			throw formatted_error(FMT_STRING("MultiByteToWideChar 2 failed."));

		return ret;
	}
#endif

	void client_thread_pimpl::run() {
		while (!constructor_done) { } // use spinlock to avoid race condition in constructor

#ifdef _WIN32
		if (_SetThreadDescription) {
			try {
				auto desc = utf8_to_utf16(fmt::format("wscpp thread ({})", parent.ip_addr_string()));
				_SetThreadDescription(GetCurrentThread(), (PCWSTR)desc.c_str());
			} catch (...) {
			}
		}
#endif

		try {
			exception_ptr except;

			thread_id = this_thread::get_id();

			while (open && state == state_enum::http) {
				recvbuf += recv();

				process_http_messages();
			}

			if (open && state == state_enum::websocket) {
				try {
					websocket_loop();
				} catch (...) {
					except = current_exception();
				}
			}

			if (disconn_handler)
				disconn_handler(parent, except);

			thread del_thread([&]() {
				unique_lock<shared_mutex> guard(serv.impl->vector_mutex);

				for (auto it = serv.impl->client_threads.begin(); it != serv.impl->client_threads.end(); it++) {
					if (it->impl->thread_id == thread_id) {
						serv.impl->client_threads.erase(it);
						break;
					}
				}
			});

			del_thread.detach();
		} catch (const exception& e) {
			cerr << e.what() << endl;
#ifdef _WIN32
			closesocket(fd);
#else
			::close(fd);
#endif
		}
	}

	void client_thread::send(const string_view& payload, enum opcode opcode) const {
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

	void client_thread_pimpl::send_raw(string_view sv) const {
		do {
			int bytes = send(fd, sv.data(), (int)sv.length(), 0);

#ifdef _WIN32
			if (bytes == SOCKET_ERROR)
				throw formatted_error(FMT_STRING("send failed ({})."), wsa_error_to_string(WSAGetLastError()));
#else
			if (bytes == -1)
				throw formatted_error(FMT_STRING("send failed ({})."), errno_to_string(errno));
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
			throw formatted_error(FMT_STRING("WideCharToMultiByte 1 failed."));

		ret.resize(len);

		len = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)s.data(), (int)s.length(), ret.data(), len,
								nullptr, nullptr);

		if (len == 0)
			throw formatted_error(FMT_STRING("WideCharToMultiByte 2 failed."));

		return ret;
	}

	void client_thread_pimpl::get_username(HANDLE token) {
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
				throw formatted_error(FMT_STRING("GetTokenInformation failed (last error {})"), le);
		}

		buf.resize(ret);
		tu = (TOKEN_USER*)&buf[0];

		if (GetTokenInformation(token, TokenUser, tu, buf.size(), &ret) == 0)
			throw formatted_error(FMT_STRING("GetTokenInformation failed (last error {})"), GetLastError());

		if (!IsValidSid(tu->User.Sid))
			throw formatted_error(FMT_STRING("Invalid SID."));

		user_size = sizeof(usernamew) / sizeof(WCHAR);
		domain_size = sizeof(domain_namew) / sizeof(WCHAR);

		if (!LookupAccountSidW(nullptr, tu->User.Sid, usernamew, &user_size, domain_namew,
							   &domain_size, &use))
			throw formatted_error(FMT_STRING("LookupAccountSid failed (last error {})"), GetLastError());

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
			throw formatted_error(FMT_STRING("getaddrinfo failed for {} (error {})."), hostname, err);

		if (!info)
			throw formatted_error(FMT_STRING("Could not get fully-qualified domain name."));

		string ret = info->ai_canonname;

		freeaddrinfo(info);

		return ret;
	}
#endif

	void client_thread_pimpl::handle_handshake(map<string, string>& headers) {
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
						throw formatted_error(FMT_STRING("DsServerRegisterSpn returned {}"), ret);
				}

				sec_status = AcquireCredentialsHandleW(nullptr, (SEC_WCHAR*)utf8_to_utf16(auth_type).c_str(), SECPKG_CRED_INBOUND,
													   nullptr, nullptr, nullptr, nullptr, &cred_handle, &timestamp);
				if (FAILED(sec_status))
					throw formatted_error(FMT_STRING("AcquireCredentialsHandle returned {}"), (enum sec_error)sec_status);
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
				throw formatted_error(FMT_STRING("AcceptSecurityContext returned {}"), (enum sec_error)sec_status);

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
					throw formatted_error(FMT_STRING("QuerySecurityContextToken returned {}"), (enum sec_error)sec_status);

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

		if (headers.count("Upgrade") == 0 || lower(headers["Upgrade"]) != "websocket" || headers.count("Sec-WebSocket-Key") == 0 || headers.count("Sec-WebSocket-Version") == 0) {
			send_raw("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
			return;
		}

		unsigned int version = stoul(headers["Sec-WebSocket-Version"]);

		if (version > 13) {
			send_raw("HTTP/1.1 400 Bad Request\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\n\r\n");
			return;
		}

		string resp = b64encode(sha1(headers["Sec-WebSocket-Key"] + MAGIC_STRING));

		send_raw("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + resp + "\r\n\r\n");

		state = state_enum::websocket;
		recvbuf = "";

		if (conn_handler)
			conn_handler(parent);
	}

	void client_thread_pimpl::internal_server_error(const string& s) {
		try {
			send_raw("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: " + to_string(s.size()) + "\r\nConnection: close\r\n\r\n" + s);
		} catch (...) {
		}
	}

	string client_thread_pimpl::recv(unsigned int len) {
		string s;
		int bytes, err = 0;

		if (len == 0)
			len = 4096;

		s.resize(len);

		bytes = ::recv(fd, s.data(), len, 0);

#ifdef _WIN32
		if (bytes == SOCKET_ERROR)
			err = WSAGetLastError();

		if (bytes == 0 || (bytes == SOCKET_ERROR && err == WSAECONNRESET)) {
			open = false;
			return "";
		} else if (bytes == SOCKET_ERROR)
			throw formatted_error(FMT_STRING("recv failed ({})."), wsa_error_to_string(err));
#else
		if (bytes == -1)
			err = errno;

		if (bytes == 0 || (bytes == -1 && err == ECONNRESET)) {
			open = false;
			return "";
		} else if (bytes == -1)
			throw formatted_error(FMT_STRING("recv failed ({})."), errno_to_string(err));
#endif

		return s.substr(0, bytes);
	}

	void client_thread_pimpl::process_http_message(const string& mess) {
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

	void client_thread_pimpl::process_http_messages() {
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

	void client_thread_pimpl::parse_ws_message(enum opcode opcode, const string& payload) {
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

	string client_thread_pimpl::recv_full(unsigned int len) {
		string s;

		while (true) {
			s += recv(len - s.length());

			if (!open)
				return "";

			if (s.length() >= len)
				return s;
		}
	}

	void client_thread_pimpl::websocket_loop() {
		while (open) {
			string header = recv_full(2);

			if (!open)
				break;

			bool fin = (header[0] & 0x80) != 0;
			auto opcode = (enum opcode)(uint8_t)(header[0] & 0xf);
			bool mask = (header[1] & 0x80) != 0;
			uint64_t len = header[1] & 0x7f;

			if (len == 126) {
				string extlen = recv_full(2);

				if (!open)
					break;

				len = ((uint8_t)extlen[0] << 8) | (uint8_t)extlen[1];
			} else if (len == 127) {
				string extlen = recv_full(8);

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
				mask_key = recv_full(4);

				if (!open)
					break;
			}

			string payload = len == 0 ? "" : recv_full((unsigned int)len);

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
			throw formatted_error(FMT_STRING("WSAStartup failed."));
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
				throw formatted_error(FMT_STRING("socket failed."));

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
						unique_lock<shared_mutex> guard(impl->vector_mutex);

						impl->client_threads.emplace_back(&newsock, *this, their_addr.sin6_addr.s6_addr, impl->msg_handler,
														  impl->conn_handler, impl->disconn_handler);
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
		std::shared_lock<std::shared_mutex> guard(impl->vector_mutex);

		for (auto& ct : impl->client_threads) {
			if (ct.impl->state == client_thread_pimpl::state_enum::websocket)
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

	server::server(uint16_t port, int backlog, const server_msg_handler& msg_handler,
		       const server_conn_handler& conn_handler, const server_disconn_handler& disconn_handler,
			   const string_view& auth_type) {
		impl = new server_pimpl(port, backlog, msg_handler, conn_handler, disconn_handler, auth_type);
	}

	server::~server() {
		delete impl;
	}

	client_thread::client_thread(void* sock, server& serv, const std::span<uint8_t, 16>& ip_addr, const server_msg_handler& msg_handler,
								 const server_conn_handler& conn_handler, const server_disconn_handler& disconn_handler) {
#ifdef _WIN32
		auto fd = *(SOCKET*)sock;
#else
		auto fd = *(int*)sock;
#endif

		impl = new client_thread_pimpl(*this, fd, serv, ip_addr, msg_handler, conn_handler, disconn_handler);
	}

	string_view client_thread::username() const {
		return impl->username;
	}

	string_view client_thread::domain_name() const {
		return impl->domain_name;
	}

#ifdef _WIN32
	void client_thread_pimpl::impersonate() const {
		SECURITY_STATUS sec_status;

		if (!ctx_handle_set)
			throw formatted_error(FMT_STRING("ctx_handle not set"));

		sec_status = ImpersonateSecurityContext((PCtxtHandle)&ctx_handle);

		if (FAILED(sec_status))
			throw formatted_error(FMT_STRING("ImpersonateSecurityContext returned {}"), (enum sec_error)sec_status);
	}

	void client_thread_pimpl::revert() const {
		SECURITY_STATUS sec_status;

		if (!ctx_handle_set)
			throw formatted_error(FMT_STRING("ctx_handle not set"));

		sec_status = RevertSecurityContext((PCtxtHandle)&ctx_handle);

		if (FAILED(sec_status))
			throw formatted_error(FMT_STRING("RevertSecurityContext returned {}"), (enum sec_error)sec_status);
	}

	void client_thread::impersonate() const {
		impl->impersonate();
	}

	void client_thread::revert() const {
		impl->revert();
	}

	HANDLE client_thread_pimpl::impersonation_token() const {
		return token.get();
	}

	HANDLE client_thread::impersonation_token() const {
		return impl->impersonation_token();
	}
#endif

	span<uint8_t, 16> client_thread::ip_addr() const {
		while (!impl->constructor_done) { } // use spinlock to avoid race condition in constructor

		return impl->ip_addr;
	}

	string client_thread::ip_addr_string() const {
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

#ifdef _WIN32 // FIXME - how do we get this to run if linked statically?
__declspec(dllexport) BOOL _stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		auto h = LoadLibraryW(L"kernelbase.dll");

		if (h)
			_SetThreadDescription = (decltype(_SetThreadDescription))(void(*)(void))GetProcAddress(h, "SetThreadDescription");
	}

	return TRUE;
}
#endif
