#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "device_identity.hpp"

namespace cg {

struct OutboxItem {
  int64_t id = 0;
  std::string dedupe_key;
  std::string body_json;
  int attempts = 0;
  std::string last_error;
  int64_t created_at = 0;
  int64_t next_attempt_at = 0;
};

class Store {
 public:
  Store() = default;
  ~Store();

  bool Open(const std::string& db_path, std::string& err);
  void Close();

  bool SaveCredential(const Credential& c, std::string& err);
  bool LoadCredential(Credential& out, std::string& err);
  bool HasCredential();

  bool Enqueue(const std::string& dedupe_key, const std::string& body_json, std::string& err);
  bool SeenDedupe(const std::string& dedupe_key);
  std::vector<OutboxItem> DueOutbox(int limit, int64_t now);
  bool MarkOutboxOk(int64_t id, std::string& err);
  bool MarkOutboxFail(int64_t id, const std::string& error, int64_t next_attempt_at, std::string& err);

 private:
  void* db_ = nullptr;  // sqlite3*
};

}  // namespace cg
