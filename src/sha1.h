/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

#pragma once

#include <string>
#include <array>

std::array<uint8_t, 20> sha1(const std::string& s);
