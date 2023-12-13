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
#include "wsclient-impl.h"
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

#ifdef _WIN32
static __inline string utf16_to_utf8(u16string_view s) {
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

#ifdef _WIN32
static void get_username(ws::server_client_pimpl& p) {
	vector<uint8_t> buf;
	TOKEN_USER* tu;
	DWORD ret = 0;
	WCHAR usernamew[256], domain_namew[256];
	DWORD user_size, domain_size;
	SID_NAME_USE use;

	buf.resize(sizeof(TOKEN_USER));
	tu = (TOKEN_USER*)&buf[0];

	if (GetTokenInformation(p.token.get(), TokenUser, tu, (DWORD)buf.size(), &ret) == 0) {
		auto le = GetLastError();

		if (le != ERROR_INSUFFICIENT_BUFFER)
			throw formatted_error("GetTokenInformation failed (last error {})", le);
	}

	buf.resize(ret);
	tu = (TOKEN_USER*)&buf[0];

	if (GetTokenInformation(p.token.get(), TokenUser, tu, (DWORD)buf.size(), &ret) == 0)
		throw formatted_error("GetTokenInformation failed (last error {})", GetLastError());

	if (!IsValidSid(tu->User.Sid))
		throw formatted_error("Invalid SID.");

	user_size = sizeof(usernamew) / sizeof(WCHAR);
	domain_size = sizeof(domain_namew) / sizeof(WCHAR);

	if (!LookupAccountSidW(nullptr, tu->User.Sid, usernamew, &user_size, domain_namew,
						   &domain_size, &use))
		throw formatted_error("LookupAccountSid failed (last error {})", GetLastError());

	p.username = utf16_to_utf8(u16string_view((char16_t*)usernamew));
	p.domain_name = utf16_to_utf8(u16string_view((char16_t*)domain_namew));
}

static void revert(const ws::server_client_pimpl& p) {
	SECURITY_STATUS sec_status;

	if (!p.ctx_handle_set)
		throw formatted_error("ctx_handle not set");

	sec_status = RevertSecurityContext((PCtxtHandle)&p.ctx_handle);

	if (FAILED(sec_status))
		throw formatted_error("RevertSecurityContext returned {}", (enum sec_error)sec_status);
}

static HANDLE impersonation_token(const ws::server_client_pimpl& p) {
	return p.token.get();
}
#endif

static string ip_addr_string(const ws::server_client_pimpl& p) {
	static const array<uint8_t, 12> ipv4_pref = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

	if (!memcmp(p.ip_addr.data(), ipv4_pref.data(), ipv4_pref.size()))
		return format("{}.{}.{}.{}", p.ip_addr[12], p.ip_addr[13], p.ip_addr[14], p.ip_addr[15]);
	else {
		char s[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, p.ip_addr.data(), s, sizeof(s));

		return s;
	}
}

void send_raw(ws::server_client_pimpl& p, span<const uint8_t> sv) {
	if (!p.sendbuf.empty()) {
		p.sendbuf.insert(p.sendbuf.end(), sv.begin(), sv.end());
#ifdef _WIN32
		p.serv.impl->ev.set();
#endif
		return;
	}

	do {
		int bytes = send(p.fd, (char*)sv.data(), (int)sv.size(), 0);

#ifdef _WIN32
		if (bytes == SOCKET_ERROR) {
			if (WSAGetLastError() == WSAEWOULDBLOCK) {
				p.sendbuf.insert(p.sendbuf.end(), sv.begin(), sv.end());
				p.serv.impl->ev.set();
				return;
			}

			if (WSAGetLastError() == WSAECONNABORTED)
				p.open = false;

			throw formatted_error("send failed to {} ({}).", ip_addr_string(p), wsa_error_to_string(WSAGetLastError()));
		}
#else
		if (bytes == -1) {
			if (errno == EWOULDBLOCK) {
				p.sendbuf.insert(p.sendbuf.end(), sv.begin(), sv.end());
				return;
			}

			if (errno == ECONNABORTED)
				p.open = false;

			throw formatted_error("send failed to {} ({}).", ip_addr_string(p), errno_to_string(errno));
		}
#endif

		if ((size_t)bytes == sv.size())
			break;

		sv = sv.subspan(bytes);
	} while (true);
}

static void internal_server_error(ws::server_client_pimpl& p, string_view s) {
	try {
		const auto& msg = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: " + to_string(s.size()) + "\r\nConnection: close\r\n\r\n" + string(s);
		send_raw(p, span((uint8_t*)msg.data(), msg.size()));
	} catch (...) {
	}
}

static void handle_handshake(ws::server_client_pimpl& p, const map<string, string>& headers) {
	if (p.serv.impl->auth_type != ws::auth::none) {
		vector<uint8_t> auth;
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

		string auth_type_str;

		switch (p.serv.impl->auth_type) {
			case ws::auth::negotiate:
				auth_type_str = "Negotiate";
				break;

			case ws::auth::ntlm:
				auth_type_str = "NTLM";
				break;

			default:
				throw runtime_error("Unhandled auth type.");
		}

		if (headers.count("Authorization") > 0) {
			const auto& authstr = headers.at("Authorization");

			if (authstr.length() > auth_type_str.length() && authstr.substr(0, auth_type_str.length()) == auth_type_str &&
				authstr[auth_type_str.length()] == ' ') {
				auth = b64decode(authstr.substr(auth_type_str.length() + 1));
			}
		}

		if (auth.empty()) {
			const auto& msg = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: " + auth_type_str + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
			send_raw(p, span((uint8_t*)msg.data(), msg.size()));
			return;
		}

#ifdef _WIN32
		if (!SecIsValidHandle(&p.cred_handle)) {
			if (p.serv.impl->auth_type == ws::auth::negotiate) { // FIXME - log error if this fails, rather than throwing exception?
				auto ret = DsServerRegisterSpnW(DS_SPN_ADD_SPN_OP, L"HTTP", nullptr);
				if (FAILED(ret))
					throw formatted_error("DsServerRegisterSpn returned {}", ret);
			}

			sec_status = AcquireCredentialsHandleW(nullptr, (SEC_WCHAR*)utf8_to_utf16(auth_type_str).c_str(), SECPKG_CRED_INBOUND,
													nullptr, nullptr, nullptr, nullptr, &p.cred_handle, &timestamp);
			if (FAILED(sec_status))
				throw formatted_error("AcquireCredentialsHandle returned {}", (enum sec_error)sec_status);
		}
#else
		if (p.cred_handle == 0) {
			gss_buffer_desc name_buf;
			gss_name_t gss_name;
			string spn = "HTTP/" + get_fqdn();

			name_buf.length = spn.length();
			name_buf.value = (void*)spn.data();

			major_status = gss_import_name(&minor_status, &name_buf, GSS_C_NO_OID, &gss_name);
			if (major_status != GSS_S_COMPLETE)
				throw gss_error("gss_import_name", major_status, minor_status);

			major_status = gss_acquire_cred(&minor_status, gss_name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
											GSS_C_ACCEPT, &p.cred_handle, nullptr, nullptr);

			if (major_status != GSS_S_COMPLETE)
				throw gss_error("gss_acquire_cred", major_status, minor_status);
		}
#endif

#ifdef _WIN32
		inbufs[0].cbBuffer = (unsigned long)auth.size();
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

		sec_status = AcceptSecurityContext(&p.cred_handle, p.ctx_handle_set ? &p.ctx_handle : nullptr, &in,
											ASC_REQ_ALLOCATE_MEMORY, SECURITY_NATIVE_DREP, &p.ctx_handle, &out,
											&context_attr, &timestamp);

		vector<uint8_t> sspi;

		if (outbuf.cbBuffer > 0) {
			auto sp = span((uint8_t*)outbuf.pvBuffer, outbuf.cbBuffer);

			sspi.assign(sp.begin(), sp.end());
		}

		if (outbuf.pvBuffer)
			FreeContextBuffer(outbuf.pvBuffer);

		if (sec_status == SEC_E_LOGON_DENIED) {
			static const string error_msg = "Logon denied.";
			const auto& msg = "HTTP/1.1 401 Unauthorized\r\nContent-Length: " + to_string(error_msg.length()) + "\r\n\r\n" + error_msg;

			send_raw(p, span((uint8_t*)msg.data(), msg.size()));
			return;
		} else if (FAILED(sec_status))
			throw formatted_error("AcceptSecurityContext returned {}", (enum sec_error)sec_status);

		p.ctx_handle_set = true;

		if (sec_status == SEC_I_CONTINUE_NEEDED || sec_status == SEC_I_COMPLETE_AND_CONTINUE) {
			auto b64 = b64encode(sspi);

			const auto& msg = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nWWW-Authenticate: " + auth_type_str + " " + b64 + "\r\n\r\n";
			send_raw(p, span((uint8_t*)msg.data(), msg.size()));

			return;
		}

		// FIXME - SEC_I_COMPLETE_NEEDED (and SEC_I_COMPLETE_AND_CONTINUE)

		{
			HANDLE h;

			sec_status = QuerySecurityContextToken(&p.ctx_handle, &h);

			if (FAILED(sec_status))
				throw formatted_error("QuerySecurityContextToken returned {}", (enum sec_error)sec_status);

			p.token.reset(h);
		}

		get_username(p);
#else
		recv_tok.length = auth.size();
		recv_tok.value = auth.data();

		major_status = gss_accept_sec_context(&minor_status, &p.ctx_handle, p.cred_handle, &recv_tok,
												GSS_C_NO_CHANNEL_BINDINGS, &src_name, &mech_type, &send_tok,
												&ret_flags, nullptr, nullptr);

		if (major_status != GSS_S_CONTINUE_NEEDED && major_status != GSS_S_COMPLETE)
			throw gss_error("gss_accept_sec_context", major_status, minor_status);

		vector<uint8_t> outbuf;

		if (send_tok.length != 0) {
			auto sp = span((uint8_t*)send_tok.value, send_tok.length);
			outbuf.assign(sp.begin(), sp.end());

			gss_release_buffer(&minor_status, &send_tok);
		}

		if (major_status == GSS_S_CONTINUE_NEEDED) {
			auto b64 = b64encode(outbuf);

			const auto& msg = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nWWW-Authenticate: " + auth_type_str + " " + b64 + "\r\n\r\n";
			send_raw(p, span((uint8_t*)msg.data(), msg.size()));

			return;
		}

		major_status = gss_display_name(&minor_status, src_name, &name_buffer, nullptr);
		if (major_status != GSS_S_COMPLETE) {
			gss_release_name(&minor_status, &src_name);
			throw gss_error("gss_display_name", major_status, minor_status);
		}

		p.username = string((char*)name_buffer.value, name_buffer.length);

		gss_release_name(&minor_status, &src_name);
		gss_release_buffer(&minor_status, &name_buffer);

		if (p.username.find("@") != string::npos) {
			auto st = p.username.find("@");

			p.domain_name = p.username.substr(st + 1);
			p.username = p.username.substr(0, st);
		}
#endif
	}

	if (headers.count("Upgrade") == 0 || lower(headers.at("Upgrade")) != "websocket" || headers.count("Sec-WebSocket-Key") == 0 || headers.count("Sec-WebSocket-Version") == 0) {
		const auto& msg = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"s;
		send_raw(p, span((uint8_t*)msg.data(), msg.size()));
		return;
	}

	const auto& wsv = headers.at("Sec-WebSocket-Version");
	unsigned int version;

	auto [ptr, ec] = from_chars(wsv.data(), wsv.data() + wsv.length(), version);

	if (ptr != wsv.data() + wsv.length())
		throw runtime_error("Invalid Sec-WebSocket-Version value.");

	if (version > 13) {
		const auto& msg = "HTTP/1.1 400 Bad Request\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\n\r\n"s;
		send_raw(p, span((uint8_t*)msg.data(), msg.size()));
		return;
	}

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

	for (const auto& ext : exts) {
		if (ext == "permessage-deflate") {
			p.deflate = true;
			break;
		} else if (ext.starts_with("permessage-deflate;")) { // ignore any parameters
			p.deflate = true;
			break;
		}
	}
#endif

	string resp = b64encode(sha1(headers.at("Sec-WebSocket-Key") + MAGIC_STRING));
	auto msg = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + resp + "\r\n";

#ifdef WITH_ZLIB
	if (p.deflate)
		msg += "Sec-WebSocket-Extensions: permessage-deflate\r\n";
#endif

	msg += "\r\n";

	send_raw(p, span((uint8_t*)msg.data(), msg.size()));

	if (!p.open)
		return;

	p.state = p.state_enum::websocket;

	if (p.conn_handler) {
		try {
			p.conn_handler(p.parent);
		} catch (...) {
			// disconnect client if handler throws exception
			p.open = false;
		}
	}
}

static void process_http_message(ws::server_client_pimpl& p, string_view mess) {
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

			if (colon != string::npos) {
				auto name = mess.substr(nl2, colon - nl2);

				if (name == "Sec-WebSocket-Extensions" && headers.contains("Sec-WebSocket-Extensions"))
					headers.at("Sec-WebSocket-Extensions") += ", " + string{mess.substr(colon + 2, nl - colon - 2)};
				else
					headers.emplace(name, mess.substr(colon + 2, nl - colon - 2));
			}
		}

		nl2 = nl + 2;
		nl = mess.find("\r\n", nl2);
	} while (nl != string::npos);

	size_t qm = path.find("?");
	if (qm != string::npos)
		path = path.substr(0, qm);

	if (path != "/") {
		const auto& msg = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"s;
		send_raw(p, span((uint8_t*)msg.data(), msg.size()));
	} else if (verb != "GET") {
		const auto& msg = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"s;
		send_raw(p, span((uint8_t*)msg.data(), msg.size()));
	} else {
		try {
			handle_handshake(p, headers);
		} catch (const exception& e) {
			internal_server_error(p, e.what());
		} catch (...) {
			internal_server_error(p, "Unhandled exception.");
		}
	}
}

static void process_http_messages(ws::server_client_pimpl& p) {
	do {
		size_t dnl = string_view((char*)p.recvbuf.data(), p.recvbuf.size()).find("\r\n\r\n");

		if (dnl == string::npos)
			return;

		process_http_message(p, string_view((char*)p.recvbuf.data(), dnl + 2));

		vector<uint8_t> tmp{p.recvbuf.data() + dnl + 4, p.recvbuf.data() + p.recvbuf.size()};
		p.recvbuf.swap(tmp);

		if (p.state != p.state_enum::http)
			break;
	} while (true);
}

#ifdef WITH_ZLIB
static vector<uint8_t> inflate_payload(ws::server_client_pimpl& p, span<const uint8_t> comp) {
	int err;
	vector<uint8_t> ret;

	static const uint8_t last_bit[] = { 0x00, 0x00, 0xff, 0xff };

	if (!p.zstrm_in) {
		p.zstrm_in.emplace();

		auto& strm = p.zstrm_in.value();

		strm.zalloc = Z_NULL;
		strm.zfree = Z_NULL;
		strm.opaque = Z_NULL;
		strm.avail_in = 0;
		strm.next_in = Z_NULL;

		err = inflateInit2(&strm, -MAX_WBITS);
		if (err != Z_OK)
			throw formatted_error("inflateInit2 returned {}", err);
	}

	auto& strm = p.zstrm_in.value();

	auto do_inflate = [](z_stream& strm, vector<uint8_t>& ret, span<const uint8_t> comp) {
		uint8_t buf[4096];
		int err;

		do {
			strm.avail_in = (unsigned int)comp.size();
			strm.next_in = (uint8_t*)comp.data();

			do {
				if (strm.avail_in == 0)
					return;

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
static void parse_ws_message(ws::server_client_pimpl& p, enum ws::opcode opcode, bool rsv1, span<const uint8_t> payload)
#else
static void parse_ws_message(ws::server_client_pimpl& p, enum ws::opcode opcode, span<const uint8_t> payload)
#endif
{
#ifdef WITH_ZLIB
	vector<uint8_t> decomp;

	if (rsv1) {
		if (!p.deflate)
			throw runtime_error("RSV1 set unexpectedly.");

		decomp = inflate_payload(p, payload);
	}
#endif

	switch (opcode) {
		case ws::opcode::close:
			p.open = false;
			return;

		case ws::opcode::ping:
#ifdef WITH_ZLIB
			if (rsv1)
				p.parent.send(decomp, ws::opcode::pong);
			else
#endif
				p.parent.send(payload, ws::opcode::pong);
			break;

		case ws::opcode::text: {
			if (p.msg_handler) {
				try {
#ifdef WITH_ZLIB
					if (rsv1)
						p.msg_handler(p.parent, string_view((char*)decomp.data(), decomp.size()));
					else
#endif
						p.msg_handler(p.parent, string_view((char*)payload.data(), payload.size()));
				} catch (...) {
					// disconnect client if handler throws exception
					p.open = false;
					return;
				}
			}

			break;
		}

		default:
			break;
	}
}

vector<uint8_t> recv(ws::server_client_pimpl& p) {
	uint8_t s[4096];
	int bytes, err = 0;

	bytes = recv(p.fd, (char*)s, sizeof(s), 0);

#ifdef _WIN32
	if (bytes == SOCKET_ERROR)
		err = WSAGetLastError();

	if (bytes == 0 || (bytes == SOCKET_ERROR && (err == WSAECONNRESET || err == WSAECONNABORTED))) {
		p.open = false;
		return {};
	} else if (bytes == SOCKET_ERROR)
		throw formatted_error("recv failed ({}).", wsa_error_to_string(err));
#else
	if (bytes == -1)
		err = errno;

	if (bytes == 0 || (bytes == -1 && (err == ECONNRESET || err == ECONNABORTED))) {
		p.open = false;
		return {};
	} else if (bytes == -1)
		throw formatted_error("recv failed ({}).", errno_to_string(err));
#endif

	return {s, s + bytes};
}

static void read(ws::server_client_pimpl& p) {
	auto msg = recv(p);

	if (!p.open)
		return;

	p.recvbuf.insert(p.recvbuf.end(), msg.data(), msg.data() + msg.size());

	if (p.state == p.state_enum::http)
		process_http_messages(p);

	if (p.state != p.state_enum::websocket)
		return;

	while (true) {
		if (p.recvbuf.size() < 2)
			return;

		auto& h = *(ws::header*)p.recvbuf.data();
		uint64_t len = h.len;

		auto sp = span(p.recvbuf);

		sp = sp.subspan(2);

		if (len == 126) {
			if (sp.size() < 2)
				return;

			len = (sp[0] << 8) | sp[1];
			sp = sp.subspan(2);
		} else if (len == 127) {
			if (sp.size() < 8)
				return;

			len = sp[0];
			len <<= 8;
			len |= sp[1];
			len <<= 8;
			len |= sp[2];
			len <<= 8;
			len |= sp[3];
			len <<= 8;
			len |= sp[4];
			len <<= 8;
			len |= sp[5];
			len <<= 8;
			len |= sp[6];
			len <<= 8;
			len |= sp[7];

			sp = sp.subspan(8);
		}

		span<const uint8_t> mask_key;

		if (h.mask) {
			if (sp.size() < 4)
				return;

			mask_key = sp.subspan(0, 4);
			sp = sp.subspan(4);
		}

		if (sp.size() < len)
			return;

		if (h.mask && len != 0) {
			auto payload = sp.subspan(0, len);

			for (unsigned int i = 0; i < payload.size(); i++) {
				payload[i] ^= mask_key[i % 4];
			}
		}

		if (!h.fin) {
			if (h.opcode != ws::opcode::invalid)
				p.last_opcode = h.opcode;

#ifdef WITH_ZLIB
			if (!p.last_rsv1.has_value())
				p.last_rsv1 = (bool)h.rsv1;
#endif

			p.payloadbuf.insert(p.payloadbuf.end(), sp.data(), sp.data() + len);
		} else if (!p.payloadbuf.empty()) {
			p.payloadbuf.insert(p.payloadbuf.end(), sp.data(), sp.data() + len);

#ifdef WITH_ZLIB
			parse_ws_message(p, p.last_opcode, p.last_rsv1.value(), p.payloadbuf);
			p.last_rsv1.reset();
#else
			parse_ws_message(p, p.last_opcode, p.payloadbuf);
#endif
			p.payloadbuf.clear();
		} else {
#ifdef WITH_ZLIB
			parse_ws_message(p, h.opcode, h.rsv1, sp.subspan(0, len));
			p.last_rsv1.reset();
#else
			parse_ws_message(p, h.opcode, sp.subspan(0, len));
#endif
		}

		if (!p.open)
			return;

		sp = sp.subspan(len);

		vector<uint8_t> tmp{sp.data(), p.recvbuf.data() + p.recvbuf.size()};
		p.recvbuf.swap(tmp);
	}
}

static void send(ws::server_client_pimpl& p, span<const uint8_t> payload, bool rsv1, enum ws::opcode opcode) {
	size_t len = payload.size();

	if (!p.open)
		return;

	if (len <= 125) {
		ws::header h(true, rsv1, false, false, opcode, false, (uint8_t)len);

		send_raw(p, span((const uint8_t*)&h, sizeof(h)));
	} else if (len < 0x10000) {
		struct {
			ws::header h;
			uint8_t len[2];
		} msg;

		static_assert(sizeof(msg) == 4);

		msg.h = ws::header(true, rsv1, false, false, opcode, false, 126);
		msg.len[0] = (len & 0xff00) >> 8;
		msg.len[1] = len & 0xff;

		send_raw(p, span((const uint8_t*)&msg, sizeof(msg)));
	} else {
		struct {
			ws::header h;
			uint8_t len[8];
		} msg;

		static_assert(sizeof(msg) == 10);

		msg.h = ws::header(true, rsv1, false, false, opcode, false, 127);
		msg.len[0] = (uint8_t)((len & 0xff00000000000000) >> 56);
		msg.len[1] = (uint8_t)((len & 0xff000000000000) >> 48);
		msg.len[2] = (uint8_t)((len & 0xff0000000000) >> 40);
		msg.len[3] = (uint8_t)((len & 0xff00000000) >> 32);
		msg.len[4] = (uint8_t)((len & 0xff000000) >> 24);
		msg.len[5] = (uint8_t)((len & 0xff0000) >> 16);
		msg.len[6] = (uint8_t)((len & 0xff00) >> 8);
		msg.len[7] = len & 0xff;

		send_raw(p, span((const uint8_t*)&msg, sizeof(msg)));
	}

	if (!p.open)
		return;

	send_raw(p, payload);
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

#ifdef WITH_ZLIB
		if (zstrm_in)
			inflateEnd(&zstrm_in.value());

		if (zstrm_out)
			deflateEnd(&zstrm_out.value());
#endif
	}

	server_client::~server_client() {
		// needs to be defined for unique_ptr with pimpl
	}

	void server_client::send(span<const uint8_t> payload, enum opcode opcode) const {
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

			strm.avail_in = (unsigned int)payload.size();
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

			::send(*impl, span(comp.data(), comp.size() - 4), true, opcode);
		} else
#endif
			::send(*impl, payload, false, opcode);
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

					while (true) {
						auto ret = poll(&pollfds[0], pollfds.size(), -1);

						if (ret >= 0)
							break;

						if (errno == EINTR)
							continue;

						throw sockets_error("poll");
					}
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

							if (netev.lNetworkEvents & (FD_READ | FD_CLOSE))
								::read(*ct.impl);
							else if (netev.lNetworkEvents & FD_WRITE) {
								vector<uint8_t> to_send = move(ct.impl->sendbuf);

								send_raw(*ct.impl, to_send);
							}

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

							break;
						}
#else
						for (const auto& pf : pollfds) {
							if (!pf.revents)
								continue;

							for (auto& ct : impl->clients) {
								if (ct.impl->fd == pf.fd) {
									if (pf.revents & POLLIN)
										::read(*ct.impl);
									else if (pf.revents & POLLOUT) {
										vector<uint8_t> to_send = std::move(ct.impl->sendbuf);

										send_raw(*ct.impl, to_send);
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

	bool server::find_client(uint64_t client_id, const std::function<void(server_client&)>& func) const {
		bool found = false;

		unique_lock guard(impl->vector_mutex);

		for (auto& ct : impl->clients) {
			if (ct.impl->state == server_client_pimpl::state_enum::websocket && ct.impl->client_id == client_id) {
				func(ct);
				found = true;
				break;
			}
		}

		return found;
	}

	bool server::send_to_client(uint64_t client_id, span<const uint8_t> payload, enum opcode opcode) const noexcept {
		bool found = false;

		unique_lock guard(impl->vector_mutex);

		for (const auto& ct : impl->clients) {
			if (ct.impl->state == server_client_pimpl::state_enum::websocket && ct.impl->client_id == client_id) {
				found = true;

				try {
					ct.send(payload, opcode);
				} catch (...) {
					found = false;
				}

				break;
			}
		}

		return found;
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
				   auth auth_type) {
		impl = make_unique<server_pimpl>(port, backlog, msg_handler, conn_handler, disconn_handler, auth_type);
	}

	server::~server() {
		// needs to be defined for unique_ptr with pimpl
	}

	server_client::server_client(socket_t sock, server& serv, span<const uint8_t, 16> ip_addr, const server_msg_handler& msg_handler,
								 const server_conn_handler& conn_handler, const server_disconn_handler& disconn_handler) {
		impl = make_unique<server_client_pimpl>(*this, sock, serv, ip_addr, msg_handler, conn_handler, disconn_handler);
	}

	string_view server_client::username() const {
		return impl->username;
	}

	string_view server_client::domain_name() const {
		return impl->domain_name;
	}

#ifdef _WIN32
	void server_client::impersonate() const {
		SECURITY_STATUS sec_status;

		if (!impl->ctx_handle_set)
			throw formatted_error("ctx_handle not set");

		sec_status = ImpersonateSecurityContext((PCtxtHandle)&impl->ctx_handle);

		if (FAILED(sec_status))
			throw formatted_error("ImpersonateSecurityContext returned {}", (enum sec_error)sec_status);
	}

	void server_client::revert() const {
		::revert(*impl);
	}

	HANDLE server_client::impersonation_token() const {
		return ::impersonation_token(*impl);
	}
#endif

	span<uint8_t, 16> server_client::ip_addr() const {
		return impl->ip_addr;
	}

	string server_client::ip_addr_string() const {
		return ::ip_addr_string(*impl);
	}

	uint64_t server_client::client_id() const {
		return impl->client_id;
	}
}
