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
	client::client(string_view host, uint16_t port, string_view path,
				   const client_msg_handler& msg_handler, const client_disconn_handler& disconn_handler,
				   bool enc) {
		impl = make_unique<client_pimpl>(*this, host, port, path, msg_handler, disconn_handler, enc);
	}

	client::~client() {
		// needs to be defined for unique_ptr to work with impl
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
				if (getnameinfo(ai->ai_addr, (int)ai->ai_addrlen, hostname, NI_MAXHOST, nullptr, 0, 0) == 0)
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

	client_pimpl::client_pimpl(client& parent, string_view host, uint16_t port, string_view path,
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

#if defined(WITH_OPENSSL) || defined(_WIN32)
			if (enc)
				ssl = make_unique<client_ssl>(*this);
#else
			if (enc)
				throw runtime_error("Encryption requested but support has not been compiled in.");
#endif

			send_handshake();

			t = make_unique<jthread>([&]() {
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

		WSACleanup();
#endif

#ifdef WITH_ZLIB
		if (zstrm_in)
			inflateEnd(&zstrm_in.value());

		if (zstrm_out)
			deflateEnd(&zstrm_out.value());
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

		return b64encode(span((uint8_t*)rand, 16));
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

	void client_pimpl::send_raw(span<const uint8_t> s, unsigned int timeout) const {
		if (timeout != 0)
			set_send_timeout(timeout);

		try {
			auto ret = ::send(sock, (char*)s.data(), (int)s.size(), 0);

#ifdef _WIN32
			if (ret == SOCKET_ERROR)
				throw formatted_error("send failed (error {})", wsa_error_to_string(WSAGetLastError()));
#else
			if (ret == -1)
				throw formatted_error("send failed (error {})", errno_to_string(errno));
#endif

			if ((size_t)ret < s.size())
				throw formatted_error("send sent {} bytes, expected {}", ret, s.size());
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

			uint8_t s[4096];
			int bytes;

#if defined(WITH_OPENSSL) || defined(_WIN32)
			if (ssl) {
				bytes = ssl->recv(s);

				if (!open)
					return "";
			} else {
#endif
				bytes = ::recv(sock, (char*)s, sizeof(s), 0);

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
#if defined(WITH_OPENSSL) || defined(_WIN32)
			}
#endif

			recvbuf += string((char*)s, bytes);
		} while (true);
	}

#ifdef _WIN32
	void client_pimpl::send_auth_response(string_view auth_type, string_view auth_msg, const string& req) {
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
			inbufs[0].cbBuffer = (unsigned long)auth.size();
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

		vector<uint8_t> sspi;

		if (outbuf.cbBuffer > 0) {
			auto sp = span((uint8_t*)outbuf.pvBuffer, outbuf.cbBuffer);
			sspi.assign(sp.begin(), sp.end());
		}

		if (outbuf.pvBuffer)
			FreeContextBuffer(outbuf.pvBuffer);

		ctx_handle_set = true;

		if (sec_status == SEC_I_CONTINUE_NEEDED || sec_status == SEC_I_COMPLETE_AND_CONTINUE ||
			sec_status == SEC_E_OK) {
			auto b64 = b64encode(sspi);
			auto msg = req + "Authorization: " + string(auth_type) + " " + b64 + "\r\n\r\n";

#if defined(WITH_OPENSSL) || defined(_WIN32)
			if (ssl)
				ssl->send(span((uint8_t*)msg.data(), msg.size()));
			else
#endif
				send_raw(span((uint8_t*)msg.data(), msg.size()));
		}

		// FIXME - SEC_I_COMPLETE_NEEDED (and SEC_I_COMPLETE_AND_CONTINUE)?
	}
#else
	void client_pimpl::send_auth_response(string_view auth_type, string_view auth_msg, const string& req) {
		OM_uint32 major_status, minor_status;
		gss_buffer_desc recv_tok, send_tok, name_buf;
		gss_name_t gss_name;

		if (auth_type == "Negotiate" && fqdn.empty())
			throw formatted_error("Cannot do Negotiate authentication as FQDN not found.");

		if (cred_handle != 0) {
			major_status = gss_acquire_cred(&minor_status, GSS_C_NO_NAME/*FIXME?*/, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
											GSS_C_INITIATE, &cred_handle, nullptr, nullptr);

			if (major_status != GSS_S_COMPLETE)
				throw gss_error("gss_acquire_cred", major_status, minor_status);
		}

		auto auth = b64decode(auth_msg);

		recv_tok.length = auth.size();
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
			vector<uint8_t> outbuf;

			auto sp = span((uint8_t*)send_tok.value, send_tok.length);
			outbuf.assign(sp.begin(), sp.end());

			gss_release_buffer(&minor_status, &send_tok);

			auto b64 = b64encode(outbuf);
			auto msg = req + "Authorization: " + string(auth_type) + " " + b64 + "\r\n\r\n";

#ifdef WITH_OPENSSL
			if (ssl)
				ssl->send(span((uint8_t*)msg.data(), msg.size()));
			else
#endif
				send_raw(span((uint8_t*)msg.data(), msg.size()));

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
#ifdef WITH_ZLIB
					 "Sec-WebSocket-Extensions: permessage-deflate\r\n"
#endif
					 "Sec-WebSocket-Version: 13\r\n";

		{
			const auto& msg = req + "\r\n";

#if defined(WITH_OPENSSL) || defined(_WIN32)
			if (ssl)
				ssl->send(span((uint8_t*)msg.data(), msg.size()));
			else
#endif
				send_raw(span((uint8_t*)msg.data(), msg.size()));
		}

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

					if (colon != string::npos) {
						auto name = string_view(mess).substr(nl2, colon - nl2);

						if (name == "Sec-WebSocket-Extensions" && headers.contains("Sec-WebSocket-Extensions"))
							headers.at("Sec-WebSocket-Extensions") += ", " + mess.substr(colon + 2, nl - colon - 2);
						else
							headers.emplace(name, mess.substr(colon + 2, nl - colon - 2));
					}
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

#ifdef WITH_ZLIB
			vector<string_view> exts;

			if (headers.count("Sec-WebSocket-Extensions") != 0) {
				const auto& ext = headers.at("Sec-WebSocket-Extensions");
				string_view sv = ext;

				do {
					auto comma = sv.find(",");

					if (comma == string::npos)
						break;

					auto sv2 = sv.substr(0, comma);

					while (!sv2.empty() && sv2.back() == ' ') {
						sv2.remove_suffix(1);
					}

					exts.emplace_back(sv2);

					sv = sv.substr(comma + 1);

					while (!sv.empty() && sv.front() == ' ') {
						sv.remove_prefix(1);
					}

					if (sv.empty())
						break;
				} while (true);

				while (!sv.empty() && sv.front() == ' ') {
					sv.remove_prefix(1);
				}

				if (!sv.empty())
					exts.emplace_back(sv);
			}

			// FIXME - permessage-deflate parameters

			for (const auto& ext : exts) {
				if (ext == "permessage-deflate")
					deflate = true;
			}
#endif
		} while (again);
	}

	static uint32_t random_mask() {
		mt19937 rng;
		rng.seed(random_device()());
		uniform_int_distribution<mt19937::result_type> dist(0, 0xffffffff);

		return dist(rng);
	}

	static void apply_mask(uint32_t mask, span<const uint8_t> pt, span<uint8_t> buf) {
		while (pt.size() >= sizeof(uint32_t)) {
			*(uint32_t*)buf.data() = *(uint32_t*)pt.data() ^ mask;

			pt = pt.subspan(sizeof(uint32_t));
			buf = buf.subspan(sizeof(uint32_t));
		}

		if (pt.empty())
			return;

		auto mask_key = span((uint8_t*)&mask, sizeof(mask));

		for (unsigned int i = 0; i < pt.size(); i++) {
			buf[i] = pt[i] ^ mask_key[i % 4];
		}
	}

	void client_pimpl::send(span<const uint8_t> payload, enum opcode opcode, bool rsv1, unsigned int timeout) const {
		uint64_t len = payload.size();

		auto do_send = [&](span<const uint8_t> s) {
#if defined(WITH_OPENSSL) || defined(_WIN32)
			if (ssl) // FIXME - timeout
				ssl->send(s);
			else
#endif
				send_raw(s, timeout);
		};

		auto mask = random_mask();

		if (len <= 125) {
#pragma pack(push, 1)
			struct {
				header h;
				uint32_t mask;
			} msg;
#pragma pack(pop)

			static_assert(sizeof(msg) == 6);

			msg.h = header(true, rsv1, false, false, opcode, true, (uint8_t)len);
			msg.mask = mask;

			do_send(span((const uint8_t*)&msg, sizeof(msg)));
		} else if (len < 0x10000) {
#pragma pack(push, 1)
			struct {
				header h;
				uint8_t len[2];
				uint32_t mask;
			} msg;
#pragma pack(pop)

			static_assert(sizeof(msg) == 8);

			msg.h = header(true, rsv1, false, false, opcode, true, 126);
			msg.len[0] = (len & 0xff00) >> 8;
			msg.len[1] = len & 0xff;
			msg.mask = mask;

			do_send(span((const uint8_t*)&msg, sizeof(msg)));
		} else {
#pragma pack(push, 1)
			struct {
				header h;
				uint8_t len[8];
				uint32_t mask;
			} msg;
#pragma pack(pop)

			static_assert(sizeof(msg) == 14);

			msg.h = header(true, rsv1, false, false, opcode, true, 127);
			msg.len[0] = (uint8_t)((len & 0xff00000000000000) >> 56);
			msg.len[1] = (uint8_t)((len & 0xff000000000000) >> 48);
			msg.len[2] = (uint8_t)((len & 0xff0000000000) >> 40);
			msg.len[3] = (uint8_t)((len & 0xff00000000) >> 32);
			msg.len[4] = (uint8_t)((len & 0xff000000) >> 24);
			msg.len[5] = (uint8_t)((len & 0xff0000) >> 16);
			msg.len[6] = (uint8_t)((len & 0xff00) >> 8);
			msg.len[7] = (uint8_t)(len & 0xff);
			msg.mask = mask;

			do_send(span((const uint8_t*)&msg, sizeof(msg)));
		}

		vector<uint8_t> masked;

		masked.resize(payload.size());

		apply_mask(mask, payload, masked);

		do_send(masked);
	}

	void client::send(span<const uint8_t> payload, enum opcode opcode, unsigned int timeout) const {
#ifdef WITH_ZLIB
		if (impl->deflate && !payload.empty()) {
			int err;
			uint8_t buf[4096];
			vector<uint8_t> comp;

			if (!impl->zstrm_out) {
				impl->zstrm_out.emplace();

				auto& strm = impl->zstrm_out.value();

				strm.zalloc = Z_NULL;
				strm.zfree = Z_NULL;
				strm.opaque = Z_NULL;

				err = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, MAX_MEM_LEVEL,
								   Z_DEFAULT_STRATEGY);
				if (err != Z_OK)
					throw formatted_error("deflateInit2 returned {}", err);
			}

			auto& strm = impl->zstrm_out.value();

			strm.avail_in = (int)payload.size();
			strm.next_in = (uint8_t*)payload.data();

			do {
				strm.avail_out = sizeof(buf);
				strm.next_out = buf;

				err = deflate(&strm, Z_NO_FLUSH);
				if (err != Z_OK && err != Z_STREAM_END)
					throw formatted_error("deflate returned {}", err);

				comp.insert(comp.end(), buf, buf + sizeof(buf) - strm.avail_out);
			} while (strm.avail_out == 0);

			do {
				strm.avail_out = sizeof(buf);
				strm.next_out = buf;

				err = deflate(&strm, Z_SYNC_FLUSH);
				if (err != Z_OK && err != Z_STREAM_END)
					throw formatted_error("deflate returned {}", err);

				comp.insert(comp.end(), buf, buf + sizeof(buf) - strm.avail_out);
			} while (strm.avail_out == 0);

			if (comp.size() < 4 || *(uint32_t*)&comp[comp.size() - 4] != 0xffff0000)
				throw runtime_error("Compressed message did not end with 00 00 ff ff.");

			impl->send(span(comp.data(), comp.size() - 4), opcode, true, timeout);
		} else
#endif
			impl->send(payload, opcode, false, timeout);
	}

	void client_pimpl::recv(span<uint8_t> sp) {
		int bytes, err = 0;

		if (sp.empty())
			return;

		if (!recvbuf.empty()) {
			auto to_copy = min(sp.size(), recvbuf.length());

			memcpy(sp.data(), recvbuf.data(), to_copy);
			recvbuf = recvbuf.substr(to_copy);

			if (sp.size() == to_copy)
				return;

			sp = sp.subspan(to_copy);
		}

		do {
#if defined(WITH_OPENSSL) || defined(_WIN32)
			if (ssl) {
				bytes = ssl->recv(sp);

				if (open)
					return;
			} else {
#endif
				bytes = ::recv(sock, (char*)sp.data(), (int)sp.size(), 0);
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

				sp = sp.subspan(bytes);
#if defined(WITH_OPENSSL) || defined(_WIN32)
			}
#endif
		} while (!sp.empty());

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

#ifdef WITH_ZLIB
	vector<uint8_t> client_pimpl::inflate_payload(span<const uint8_t> comp) {
		int err;
		vector<uint8_t> ret;

		static const uint8_t last_bit[] = { 0x00, 0x00, 0xff, 0xff };

		if (!zstrm_in) {
			zstrm_in.emplace();

			auto& strm = zstrm_in.value();

			strm.zalloc = Z_NULL;
			strm.zfree = Z_NULL;
			strm.opaque = Z_NULL;
			strm.avail_in = 0;
			strm.next_in = Z_NULL;

			err = inflateInit2(&strm, -MAX_WBITS);
			if (err != Z_OK)
				throw formatted_error("inflateInit2 returned {}", err);
		}

		auto& strm = zstrm_in.value();

		auto do_inflate = [](z_stream& strm, vector<uint8_t>& ret, span<const uint8_t> comp) {
			uint8_t buf[4096];
			int err;

			do {
				strm.avail_in = comp.size();

				if (strm.avail_in == 0)
					break;

				strm.next_in = (uint8_t*)comp.data();

				do {
					if (strm.avail_in == 0)
						break;

					strm.avail_out = sizeof(buf);
					strm.next_out = buf;
					err = inflate(&strm, Z_NO_FLUSH);

					if (err != Z_OK && err != Z_STREAM_END)
						throw formatted_error("inflate returned {}", err);

					ret.insert(ret.end(), buf, buf + sizeof(buf) - strm.avail_out);
				} while (strm.avail_out == 0);

				comp = comp.subspan(comp.size() - strm.avail_in);
			} while (err != Z_STREAM_END);
		};

		do_inflate(strm, ret, comp);
		do_inflate(strm, ret, last_bit);

		return ret;
	}
#endif

#ifdef WITH_ZLIB
	void client_pimpl::parse_ws_message(enum opcode opcode, bool rsv1, span<const uint8_t> payload)
#else
	void client_pimpl::parse_ws_message(enum opcode opcode, span<const uint8_t> payload)
#endif
	{
#ifdef WITH_ZLIB
		vector<uint8_t> decomp;

		if (rsv1) {
			if (!deflate)
				throw runtime_error("RSV1 set unexpectedly.");

			decomp = inflate_payload(payload);
		}
#endif

		switch (opcode) {
			case opcode::close:
				open = false;
				return;

			case opcode::ping:
#ifdef WITH_ZLIB
				if (rsv1)
					parent.send(decomp, opcode::pong);
				else
#endif
					parent.send(payload, opcode::pong);
				break;

			case opcode::pong:
				if (ping_sem.has_value())
					ping_sem->release();
				break;

			default:
				break;
		}

		if (msg_handler) {
#ifdef WITH_ZLIB
			if (rsv1)
				msg_handler(parent, string_view((char*)decomp.data(), decomp.size()), opcode);
			else
#endif
				msg_handler(parent, string_view((char*)payload.data(), payload.size()), opcode);
		}
	}

	void client_pimpl::recv_thread() {
		vector<uint8_t> payloadbuf;

		while (open) {
			header h;

			recv(span((uint8_t*)&h, sizeof(header)));

			if (!open)
				break;

			auto len = (uint64_t)h.len;

			if (len == 126) {
				uint16_t extlen;

				recv(span((uint8_t*)&extlen, sizeof(extlen)));

				if (!open)
					break;

#ifdef _MSC_VER
				len = _byteswap_ushort(extlen);
#else
				len = __builtin_bswap16(extlen);
#endif
			} else if (len == 127) {
				uint64_t extlen;

				recv(span((uint8_t*)&extlen, sizeof(extlen)));

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
				recv(span((uint8_t*)&mask_key, sizeof(mask_key)));

				if (!open)
					break;
			}

			vector<uint8_t> payload;

			if (len > 0) {
				payload.resize(len);
				recv(payload);
			}

			if (!open)
				break;

			if (h.mask) {
				// FIXME - speed this up by treating mask_key as uint32_t?
				for (unsigned int i = 0; i < payload.size(); i++) {
					payload[i] ^= mask_key[i % 4];
				}
			}

			if (!h.fin) {
				if (h.opcode != opcode::invalid)
					last_opcode = h.opcode;

				payloadbuf.insert(payloadbuf.end(), payload.data(), payload.data() + payload.size());

#ifdef WITH_ZLIB
				if (!last_rsv1.has_value())
					last_rsv1 = (bool)h.rsv1;
#endif
			} else if (!payloadbuf.empty()) {
				payloadbuf.insert(payloadbuf.end(), payload.data(), payload.data() + payload.size());
#ifdef WITH_ZLIB
				parse_ws_message(last_opcode, last_rsv1.value(), payloadbuf);
				last_rsv1.reset();
#else
				parse_ws_message(last_opcode, payloadbuf);
#endif
				payloadbuf.clear();
			} else {
#ifdef WITH_ZLIB
				parse_ws_message(h.opcode, h.rsv1, payload);
#else
				parse_ws_message(h.opcode, payload);
#endif
			}
		}
	}

	void client::join() const {
		if (impl->t)
			impl->t->join();
	}

	bool client::is_open() const {
		return impl->open;
	}

	void client::ping(unsigned int timeout_ms) const {
		impl->ping_sem.emplace(0);

		// FIXME - not thread-safe?

		auto& sem = impl->ping_sem.value();

		send("", ws::opcode::ping);

		if (timeout_ms == 0) {
			sem.acquire();
			impl->ping_sem.reset();
		} else {
			bool waited = sem.try_acquire_for(chrono::milliseconds{timeout_ms});

			impl->ping_sem.reset();

			if (!waited)
				throw runtime_error("Timeout.");
		}
	}
}
