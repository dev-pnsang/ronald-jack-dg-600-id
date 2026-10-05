#pragma once

#include <cstdint>
#include <mutex>
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

struct OpsLogItem {
  int64_t id = 0;
  std::string ts_iso;
  std::string level;
  std::string component;
  std::string code;
  std::string message;
  std::string fields_json;
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
  // Rows with next_attempt_at <= now. max_attempts <= 0 means no attempt cap.
  std::vector<OutboxItem> DueOutbox(int limit, int64_t now, int max_attempts);
  bool MarkOutboxOk(int64_t id, std::string& err);
  bool MarkOutboxFail(int64_t id, const std::string& error, int64_t next_attempt_at, std::string& err);
  // Keep the punch. Schedule a slow retry. Never deletes the row.
  bool AbandonOutbox(int64_t id, const std::string& error, std::string& err);

  // Delete seen rows older than cutoff. Unsent outbox rows are never deleted.
  int Prune(int64_t older_than_unix, std::string& err);

  bool SetMeta(const std::string& key, const std::string& value, std::string& err);
  bool GetMeta(const std::string& key, std::string& value, std::string& err);

  bool EnqueueOpsLog(const std::string& level, const std::string& component,
                     const std::string& code, const std::string& message,
                     const std::string& fields_json, std::string& err);
  std::vector<OpsLogItem> DueOpsLogs(int limit);
  bool DeleteOpsLogs(const std::vector<int64_t>& ids, std::string& err);

 private:
  void* db_ = nullptr;  // sqlite3*
  std::string db_path_;
  std::recursive_mutex mu_;
};

}  // namespace cg
