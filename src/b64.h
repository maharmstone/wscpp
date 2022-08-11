#pragma once

#include <string>
#include <vector>
#include <span>

std::string b64encode(std::span<const uint8_t> sv);
std::vector<uint8_t> b64decode(std::string_view sv);
