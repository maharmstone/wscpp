#ifdef _WIN32
#include <WinSock2.h>
#include <ws2ipdef.h>
#endif
#include "wscpp.h"

namespace ws {
#ifdef _WIN32
    sockets_error::sockets_error(const char* func) : err(WSAGetLastError()), msg(std::string(func) + " failed (error " + std::to_string(err) + ")") {
#else
    sockets_error::sockets_error(const char* func) : err(errno), msg(std::string(func) + " failed (error " + std::to_string(err) + ")") {
#endif
    }
}
