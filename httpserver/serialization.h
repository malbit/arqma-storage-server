#pragma once

#include <string>
#include <vector>

namespace arqma {

namespace storage {
struct Item;
}

struct message_t;

void serialize_message(std::string& buf, const storage::Item& msg);
std::vector<std::string> serialize_messages(const std::vector<storage::Item>& msgs);
std::vector<storage::Item> deserialize_messages(std::string_view blob);

} // namespace arqma
