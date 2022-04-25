#pragma once

#include "wscpp.h"
#include <thread>
#include <bit>

#ifdef _WIN32
#define SECURITY_WIN32
#include <sspi.h>
#endif

#ifndef _WIN32
#define INVALID_SOCKET -1
#include <gssapi/gssapi.h>
#endif

#include "config.h"

#ifdef WITH_OPENSSL
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#endif

#ifdef WITH_OPENSSL
class bio_meth_deleter {
public:
	typedef BIO_METHOD* pointer;

	void operator()(BIO_METHOD* meth) {
		BIO_meth_free(meth);
	}
};

class ssl_deleter {
public:
	typedef SSL* pointer;

	void operator()(SSL* ssl) {
		SSL_free(ssl);
	}
};

class ssl_ctx_deleter {
public:
	typedef SSL_CTX* pointer;

	void operator()(SSL_CTX* ctx) {
		SSL_CTX_free(ctx);
	}
};
#endif

#ifdef _WIN32
static __inline std::u16string utf8_to_utf16(std::string_view s) {
	std::u16string ret;

	if (s.empty())
		return u"";

	auto len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.length(), nullptr, 0);

	if (len == 0)
		throw std::runtime_error("MultiByteToWideChar 1 failed.");

	ret.resize(len);

	len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.length(), (wchar_t*)ret.data(), len);

	if (len == 0)
		throw std::runtime_error("MultiByteToWideChar 2 failed.");

	return ret;
}
#endif

namespace ws {
	struct header {
		header() = default;

		constexpr header(bool fin, enum opcode opcode, bool mask, uint8_t len) :
			opcode(opcode), fin(fin), len(len), mask(mask) { }

		enum opcode opcode : 7;
		bool fin : 1;
		uint8_t len : 7;
		bool mask : 1;
	};

	static_assert(sizeof(header) == 2);
	static_assert(std::bit_cast<uint16_t, header>(header(false, opcode::invalid, false, 0)) == 0x0000);
	static_assert(std::bit_cast<uint16_t, header>(header(false, opcode::text, false, 0)) == 0x0001);
	static_assert(std::bit_cast<uint16_t, header>(header(true, opcode::text, false, 0)) == 0x0081);
	static_assert(std::bit_cast<uint16_t, header>(header(false, opcode::invalid, false, 0x7f)) == 0x7f00);
	static_assert(std::bit_cast<uint16_t, header>(header(false, opcode::text, false, 0x7f)) == 0x7f01);
	static_assert(std::bit_cast<uint16_t, header>(header(true, opcode::text, false, 0x7f)) == 0x7f81);
	static_assert(std::bit_cast<uint16_t, header>(header(false, opcode::invalid, true, 0x7f)) == 0xff00);
	static_assert(std::bit_cast<uint16_t, header>(header(false, opcode::text, true, 0x7f)) == 0xff01);
	static_assert(std::bit_cast<uint16_t, header>(header(true, opcode::text, true, 0x7f)) == 0xff81);

	class client_pimpl;

#if defined(WITH_OPENSSL) || defined(_WIN32)
	class client_ssl {
	public:
		client_ssl(client_pimpl& client);
#ifdef WITH_OPENSSL
		int ssl_read_cb(char* data, int len);
		int ssl_write_cb(std::string_view sv);
		long ssl_ctrl_cb(int cmd, long num, void* ptr);
		int ssl_verify_cb(int preverify, X509_STORE_CTX* x509_ctx);
#else
		~client_ssl();
		void recv_raw(void* buf, size_t length);
#endif
		void send(std::string_view sv);
		unsigned int recv(unsigned int len, void* buf);

		std::exception_ptr exception;

	private:
		client_pimpl& client;
		std::string ssl_recv_buf;
#ifdef WITH_OPENSSL
		BIO* bio;
		std::unique_ptr<SSL_CTX*, ssl_ctx_deleter> ctx;
		std::unique_ptr<BIO_METHOD*, bio_meth_deleter> meth;
		std::unique_ptr<SSL*, ssl_deleter> ssl;
#else
		CredHandle cred_handle = {(ULONG_PTR)-1, (ULONG_PTR)-1};
		CtxtHandle ctx_handle;
		bool ctx_handle_set = false;
		SecPkgContext_StreamSizes stream_sizes;
#endif
	};
#endif

	class client_pimpl {
	public:
		client_pimpl(client& parent, const std::string& host, uint16_t port, const std::string& path,
					 const client_msg_handler& msg_handler, const client_disconn_handler& disconn_handler,
					 bool enc);
		~client_pimpl();

		void open_connexion();
		void send_auth_response(std::string_view auth_type, std::string_view auth_msg, const std::string& req);
		void send_handshake();
		std::string random_key();
		void send_raw(std::string_view s, unsigned int timeout = 0) const;
		void set_send_timeout(unsigned int timeout) const;
		std::string recv_http();
		void recv_thread();
		void recv(unsigned int len, void* buf);
		void parse_ws_message(enum opcode opcode, const std::string& payload);

		client& parent;
		std::string host;
		uint16_t port;
		std::string path;
		client_msg_handler msg_handler;
		client_disconn_handler disconn_handler;
		socket_t sock = INVALID_SOCKET;
#ifdef _WIN32
		CredHandle cred_handle = {(ULONG_PTR)-1, (ULONG_PTR)-1};
		CtxtHandle ctx_handle;
		bool ctx_handle_set = false;
#else
		gss_cred_id_t cred_handle = 0;
		gss_ctx_id_t ctx_handle = GSS_C_NO_CONTEXT;
#endif
		bool open = false;
		std::unique_ptr<std::jthread> t;
		std::string fqdn;
		enum opcode last_opcode;
		std::string recvbuf;
#if defined(WITH_OPENSSL) || defined(_WIN32)
		std::unique_ptr<client_ssl> ssl;
#endif
    };
}
