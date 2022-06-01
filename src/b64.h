#pragma once

#include <string>
#include <span>

std::string b64encode(std::span<const uint8_t> sv);
std::string b64decode(std::string_view sv);
