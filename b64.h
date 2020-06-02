#pragma once

#include <string>

std::string b64encode(const std::string_view& sv);
std::string b64decode(const std::string_view& sv);
