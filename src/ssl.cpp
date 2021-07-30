#include "wsclient-impl.h"
#include "wsexcept.h"
#include <string.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#endif

using namespace std;

class ssl_error : public exception {
public:
	ssl_error(const char* func, unsigned long err) {
		auto str = ERR_reason_error_string(err);

		if (str)
			msg = str;
		else
			msg = func + " failed: "s + to_string(err);
	}

	const char* what() const noexcept {
		return msg.c_str();
	}

private:
	string msg;
};

static int ssl_bio_read(BIO* bio, char* data, int len) noexcept {
	auto& c = *(ws::client_ssl*)BIO_get_data(bio);

	try {
		return c.ssl_read_cb(data, len);
	} catch (...) {
		c.exception = current_exception();
		return -1;
	}
}

static int ssl_bio_write(BIO* bio, const char* data, int len) noexcept {
	auto& c = *(ws::client_ssl*)BIO_get_data(bio);

	try {
		return c.ssl_write_cb(string_view{data, (size_t)len});
	} catch (...) {
		c.exception = current_exception();
		return -1;
	}
}

static long ssl_bio_ctrl(BIO* bio, int cmd, long num, void* ptr) noexcept {
	auto& c = *(ws::client_ssl*)BIO_get_data(bio);

	try {
		return c.ssl_ctrl_cb(cmd, num, ptr);
	} catch (...) {
		c.exception = current_exception();
		return -1;
	}
}

namespace ws {
	int client_ssl::ssl_read_cb(char* data, int len) {
		int copied = 0;

		if (len == 0)
			return 0;

		if (!ssl_recv_buf.empty()) {
			auto to_copy = min(len, (int)ssl_recv_buf.length());

			memcpy(data, ssl_recv_buf.data(), to_copy);
			ssl_recv_buf = ssl_recv_buf.substr(to_copy);

			if (len == to_copy)
				return len;

			len -= to_copy;
			copied = to_copy;
			data += to_copy;
		}

		auto ret = ::recv(client.sock, data, len, 0);

#ifdef _WIN32
		if (ret == SOCKET_ERROR) {
			auto err = WSAGetLastError();

			if (err == WSAECONNRESET) {
				client.open = false;
				return copied;
			}

			throw formatted_error("recv failed ({})", wsa_error_to_string(err));
		}
#else
		if (ret == -1) {
			if (errno == ECONNRESET) {
				client.open = false;
				return copied;
			}

			throw formatted_error("recv failed ({})", errno_to_string(errno));
		}
#endif

		if (ret == 0) {
			client.open = false;
			return copied;
		}

		copied += ret;

		return copied;
	}

	int client_ssl::ssl_write_cb(const string_view& sv) {
		client.send_raw(sv);

		return (int)sv.length();
	}

	long client_ssl::ssl_ctrl_cb(int cmd, long, void*) {
		switch (cmd) {
			case BIO_CTRL_FLUSH:
				return 1;

			case BIO_C_DO_STATE_MACHINE: {
				auto ret = SSL_do_handshake(ssl.get());

				if (ret != 1)
					throw formatted_error("SSL_do_handshake failed (error {})", SSL_get_error(ssl.get(), ret));

				return 1;
			}
		}

		return 0;
	}

	client_ssl::client_ssl(client_pimpl& client) : client(client) {
		ctx.reset(SSL_CTX_new(SSLv23_method()));
		if (!ctx)
			throw ssl_error("SSL_CTX_new", ERR_get_error());

		// FIXME - verify certificate?
// 		ctx.set_verify(SSL_VERIFY_PEER, verify_callback);
// 		ctx.set_verify_depth(5);

		SSL_CTX_set_options(ctx.get(), SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

		meth.reset(BIO_meth_new(BIO_TYPE_MEM, "wscpp"));
		if (!meth)
			throw ssl_error("BIO_meth_new", ERR_get_error());

		BIO_meth_set_read(meth.get(), ssl_bio_read);
		BIO_meth_set_write(meth.get(), ssl_bio_write);
		BIO_meth_set_ctrl(meth.get(), ssl_bio_ctrl);
		BIO_meth_set_destroy(meth.get(), [](BIO*) {
			return 1;
		});

		bio = BIO_new(meth.get());
		if (!bio)
			throw ssl_error("BIO_new", ERR_get_error());

		BIO_set_data(bio, this);

		ssl.reset(SSL_new(ctx.get()));
		if (!ssl) {
			BIO_free_all(bio);
			throw ssl_error("SSL_new", ERR_get_error());
		}

		SSL_set_bio(ssl.get(), bio, bio);

		// FIXME - SSL_set_tlsext_host_name?

		SSL_set_connect_state(ssl.get());

		SSL_connect(ssl.get());
		if (exception)
			rethrow_exception(exception);

		if (BIO_do_connect(bio) != 1) {
			if (exception)
				rethrow_exception(exception);

			throw ssl_error("BIO_do_connect", ERR_get_error());
		}

		if (BIO_do_handshake(bio) != 1) {
			if (exception)
				rethrow_exception(exception);

			throw ssl_error("BIO_do_handshake", ERR_get_error());
		}
	}

	void client_ssl::send(std::string_view sv) {
		while (!sv.empty()) {
			auto ret = SSL_write(ssl.get(), sv.data(), (int)sv.length());

			if (ret <= 0) {
				if (exception)
					rethrow_exception(exception);

				throw formatted_error("SSL_write failed (error {})", SSL_get_error(ssl.get(), ret));
			}

			sv = sv.substr(ret);
		}
	}

	unsigned int client_ssl::recv(unsigned int len, void* buf) {
		auto ret = SSL_read(ssl.get(), buf, len);

		if (ret <= 0) {
			if (exception)
				rethrow_exception(exception);

			throw formatted_error("SSL_read failed (error {})", SSL_get_error(ssl.get(), ret));
		}

		return ret;
	}
};
