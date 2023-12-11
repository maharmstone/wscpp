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
static constexpr std::string b64encode(std::span<const uint8_t> sv) {
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
static_assert(b64encode(std::vector<uint8_t>{0xc2, 0xa3}) == "wqM=");

static constexpr int B64index[256] = {
	0,   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,   0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62, 63, 62, 62, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,
	0,   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,  0,  0,  0, 63,
	0,  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
};

static constexpr std::vector<uint8_t> b64decode(std::string_view sv) {
	auto p = (char*)sv.data();
	int pad = sv.length() > 0 && (sv.length() % 4 || p[sv.length() - 1] == '=');
	const size_t L = ((sv.length() + 3) / 4 - pad) * 4;
	std::vector<uint8_t> str;

	str.resize(L / 4 * 3 + pad);

	for (size_t i = 0, j = 0; i < L; i += 4) {
		int n = B64index[(uint8_t)p[i]] << 18 | B64index[(uint8_t)p[i + 1]] << 12 | B64index[(uint8_t)p[i + 2]] << 6 | B64index[(uint8_t)p[i + 3]];
		str[j++] = n >> 16;
		str[j++] = n >> 8 & 0xFF;
		str[j++] = n & 0xFF;
	}

	if (pad) {
		int n = B64index[(uint8_t)p[L]] << 18 | B64index[(uint8_t)p[L + 1]] << 12;
		str[str.size() - 1] = n >> 16;

		if (sv.length() > L + 2 && p[L + 2] != '=') {
			n |= B64index[(uint8_t)p[L + 2]] << 6;
			str.push_back(n >> 8 & 0xFF);
		}
	}

	return str;
}

static_assert(b64decode("") == std::vector<uint8_t>{});
static_assert(b64decode("Zg==") == std::vector<uint8_t>{'f'});
static_assert(b64decode("Zm8=") == std::vector<uint8_t>{'f','o'});
static_assert(b64decode("Zm9v") == std::vector<uint8_t>{'f','o','o'});
static_assert(b64decode("Zm9vYg==") == std::vector<uint8_t>{'f','o','o','b'});
static_assert(b64decode("Zm9vYmE=") == std::vector<uint8_t>{'f','o','o','b','a'});
static_assert(b64decode("Zm9vYmFy") == std::vector<uint8_t>{'f','o','o','b','a','r'});
static_assert(b64decode("wqM=") == std::vector<uint8_t>{0xc2, 0xa3});
