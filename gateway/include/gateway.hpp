#pragma once

#include "config.hpp"

namespace cg {

int RunGateway(const Config& cfg);
int RunEnroll(const Config& cfg, const std::string& pairing_code);

}  // namespace cg
