#pragma once

#include <fmt/format.h>

#ifndef _WIN32
#include <string>
#include <gssapi/gssapi.h>

class gss_error : public std::exception {
public:
	gss_error(const std::string& func, OM_uint32 major, OM_uint32 minor) {
		OM_uint32 message_context = 0;
		OM_uint32 min_status;
		gss_buffer_desc status_string;
		bool first = true;

		msg = func + " failed (minor " + std::to_string(minor) + "): ";

		do {
			gss_display_status(&min_status, major, GSS_C_GSS_CODE, GSS_C_NO_OID,
							   &message_context, &status_string);

			if (!first)
				msg += "; ";

			msg += std::string((char*)status_string.value, status_string.length);

			gss_release_buffer(&min_status, &status_string);
			first = false;
		} while (message_context != 0);
	}

	const char* what() const noexcept {
		return msg.c_str();
	}

private:
	std::string msg;
};
#endif

class formatted_error : public std::exception {
public:
	template<typename T, typename... Args>
	formatted_error(const T& s, Args&&... args) {
		msg = fmt::format(s, std::forward<Args>(args)...);
	}

	const char* what() const noexcept {
		return msg.c_str();
	}

private:
	std::string msg;
};
