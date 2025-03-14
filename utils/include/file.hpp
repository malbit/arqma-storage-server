#pragma once
#include <filesystem>
#include <string>
#include <string_view>

namespace arqma {

std::string slurp_file(const std::filesystem::path& file);

void dump_file(const std::filesystem::path& file, std::string_view content);

}
