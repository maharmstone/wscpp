/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

// 2016-12-12 - Gaspard Petit : Slightly modified to return a std::string
// instead of a buffer allocated with malloc.

#pragma once

#include <string>
#include <vector>
#include <span>
#include <stdint.h>

static constexpr char base64_table[65] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
* base64_encode - Base64 encode
* @src: Data to be encoded
* @len: Length of the data to be encoded
* @out_len: Pointer to output length variable, or %NULL if not used
* Returns: Allocated buffer of out_len bytes of encoded data,
* or empty string on failure
*/
constexpr std::string b64encode(std::span<const uint8_t> sv) {
	const unsigned char* src = (const unsigned char*)sv.data();
	size_t len = sv.size();
	char *out, *pos;
	const unsigned char *end, *in;

	size_t olen;

	olen = 4*((len + 2) / 3); /* 3-byte blocks to 4-byte */

	if (olen < len)
		return std::string(); /* integer overflow */

	std::string outStr;
	outStr.resize(olen);
	out = (char*)&outStr[0];

	end = src + len;
	in = src;
	pos = out;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		}
		else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
				(in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
	}

	return outStr;
}

static_assert(b64encode({}) == "");
static_assert(b64encode(std::vector<uint8_t>{'f'}) == "Zg==");
static_assert(b64encode(std::vector<uint8_t>{'f','o'}) == "Zm8=");
static_assert(b64encode(std::vector<uint8_t>{'f','o','o'}) == "Zm9v");
static_assert(b64encode(std::vector<uint8_t>{'f','o','o','b'}) == "Zm9vYg==");
static_assert(b64encode(std::vector<uint8_t>{'f','o','o','b','a',}) == "Zm9vYmE=");
static_assert(b64encode(std::vector<uint8_t>{'f','o','o','b','a','r'}) == "Zm9vYmFy");

std::vector<uint8_t> b64decode(std::string_view sv);
