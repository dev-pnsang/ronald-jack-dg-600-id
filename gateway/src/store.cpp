#include "store.hpp"

#include <sqlite3.h>
#include <sys/stat.h>

#include "util.hpp"

namespace cg {
namespace {

std::string ColText(sqlite3_stmt* st, int col) {
  const unsigned char* p = sqlite3_column_text(st, col);
  return p ? reinterpret_cast<const char*>(p) : "";
}

}  // namespace

Store::~Store() { Close(); }

bool Store::Open(const std::string& db_path, std::string& err) {
  Close();
  db_path_ = db_path;
  sqlite3* db = nullptr;
  if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
    err = db ? sqlite3_errmsg(db) : "sqlite open failed";
    if (db) sqlite3_close(db);
    return false;
  }
  db_ = db;
  ::chmod(db_path.c_str(), 0600);

  const char* schema = R"SQL(
CREATE TABLE IF NOT EXISTS credential (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  device_id TEXT,
  organization_id TEXT,
  auth_secret TEXT NOT NULL,
  signing_secret TEXT NOT NULL,
  credential_id TEXT,
  scopes_json TEXT,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dedupe_key TEXT NOT NULL UNIQUE,
  body_json TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  next_attempt_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS seen (
  dedupe_key TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
)SQL";
  char* errmsg = nullptr;
  if (sqlite3_exec(static_cast<sqlite3*>(db_), schema, nullptr, nullptr, &errmsg) != SQLITE_OK) {
    err = errmsg ? errmsg : "schema failed";
    sqlite3_free(errmsg);
    Close();
    return false;
  }
  sqlite3_exec(static_cast<sqlite3*>(db_), "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
  sqlite3_exec(static_cast<sqlite3*>(db_), "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
  return true;
}

void Store::Close() {
  if (db_) {
    sqlite3_close(static_cast<sqlite3*>(db_));
    db_ = nullptr;
  }
}

bool Store::SaveCredential(const Credential& c, std::string& err) {
  sqlite3_stmt* st = nullptr;
  const char* sql =
      "INSERT INTO credential(id, device_id, organization_id, auth_secret, signing_secret, "
      "credential_id, scopes_json, updated_at) VALUES(1,?,?,?,?,?,?,?) "
      "ON CONFLICT(id) DO UPDATE SET device_id=excluded.device_id, "
      "organization_id=excluded.organization_id, auth_secret=excluded.auth_secret, "
      "signing_secret=excluded.signing_secret, credential_id=excluded.credential_id, "
      "scopes_json=excluded.scopes_json, updated_at=excluded.updated_at";
  if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_), sql, -1, &st, nullptr) != SQLITE_OK) {
    err = sqlite3_errmsg(static_cast<sqlite3*>(db_));
    return false;
  }
  sqlite3_bind_text(st, 1, c.device_id.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 2, c.organization_id.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 3, c.auth_secret.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 4, c.signing_secret.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 5, c.credential_id.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 6, c.scopes_json.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 7, UnixNow());
  bool ok = sqlite3_step(st) == SQLITE_DONE;
  if (!ok) err = sqlite3_errmsg(static_cast<sqlite3*>(db_));
  sqlite3_finalize(st);
  if (ok && !db_path_.empty()) ::chmod(db_path_.c_str(), 0600);
  return ok;
}

bool Store::LoadCredential(Credential& out, std::string& err) {
  sqlite3_stmt* st = nullptr;
  const char* sql =
      "SELECT device_id, organization_id, auth_secret, signing_secret, credential_id, scopes_json "
      "FROM credential WHERE id=1";
  if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_), sql, -1, &st, nullptr) != SQLITE_OK) {
    err = sqlite3_errmsg(static_cast<sqlite3*>(db_));
    return false;
  }
  bool ok = false;
  if (sqlite3_step(st) == SQLITE_ROW) {
    out.device_id = ColText(st, 0);
    out.organization_id = ColText(st, 1);
    out.auth_secret = ColText(st, 2);
    out.signing_secret = ColText(st, 3);
    out.credential_id = ColText(st, 4);
    out.scopes_json = ColText(st, 5);
    ok = !out.auth_secret.empty() && !out.signing_secret.empty();
    if (!ok) err = "credential row incomplete";
  } else {
    err = "no credential enrolled";
  }
  sqlite3_finalize(st);
  return ok;
}

bool Store::HasCredential() {
  Credential c;
  std::string err;
  return LoadCredential(c, err);
}

bool Store::SeenDedupe(const std::string& dedupe_key) {
  sqlite3_stmt* st = nullptr;
  const char* sql =
      "SELECT 1 FROM seen WHERE dedupe_key=? OR EXISTS(SELECT 1 FROM outbox WHERE dedupe_key=?)";
  if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_), sql, -1, &st, nullptr) != SQLITE_OK) return false;
  sqlite3_bind_text(st, 1, dedupe_key.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 2, dedupe_key.c_str(), -1, SQLITE_TRANSIENT);
  bool seen = sqlite3_step(st) == SQLITE_ROW;
  sqlite3_finalize(st);
  return seen;
}

bool Store::Enqueue(const std::string& dedupe_key, const std::string& body_json, std::string& err) {
  if (SeenDedupe(dedupe_key)) return true;
  sqlite3_stmt* st = nullptr;
  const char* sql =
      "INSERT OR IGNORE INTO outbox(dedupe_key, body_json, attempts, created_at, next_attempt_at) "
      "VALUES(?,?,0,?,?)";
  if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_), sql, -1, &st, nullptr) != SQLITE_OK) {
    err = sqlite3_errmsg(static_cast<sqlite3*>(db_));
    return false;
  }
  int64_t now = UnixNow();
  sqlite3_bind_text(st, 1, dedupe_key.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 2, body_json.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 3, now);
  sqlite3_bind_int64(st, 4, now);
  bool ok = sqlite3_step(st) == SQLITE_DONE;
  if (!ok) err = sqlite3_errmsg(static_cast<sqlite3*>(db_));
  sqlite3_finalize(st);
  return ok;
}

std::vector<OutboxItem> Store::DueOutbox(int limit, int64_t now, int max_attempts) {
  std::vector<OutboxItem> items;
  sqlite3_stmt* st = nullptr;
  const char* sql =
      "SELECT id, dedupe_key, body_json, attempts, IFNULL(last_error,''), created_at, next_attempt_at "
      "FROM outbox WHERE next_attempt_at<=? AND attempts<? ORDER BY id ASC LIMIT ?";
  if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_), sql, -1, &st, nullptr) != SQLITE_OK) return items;
  sqlite3_bind_int64(st, 1, now);
  sqlite3_bind_int(st, 2, max_attempts > 0 ? max_attempts : 1000000);
  sqlite3_bind_int(st, 3, limit);
  while (sqlite3_step(st) == SQLITE_ROW) {
    OutboxItem it;
    it.id = sqlite3_column_int64(st, 0);
    it.dedupe_key = ColText(st, 1);
    it.body_json = ColText(st, 2);
    it.attempts = sqlite3_column_int(st, 3);
    it.last_error = ColText(st, 4);
    it.created_at = sqlite3_column_int64(st, 5);
    it.next_attempt_at = sqlite3_column_int64(st, 6);
    items.push_back(std::move(it));
  }
  sqlite3_finalize(st);
  return items;
}

bool Store::MarkOutboxOk(int64_t id, std::string& err) {
  sqlite3* db = static_cast<sqlite3*>(db_);
  if (sqlite3_exec(db, "BEGIN", nullptr, nullptr, nullptr) != SQLITE_OK) {
    err = sqlite3_errmsg(db);
    return false;
  }
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db, "SELECT dedupe_key FROM outbox WHERE id=?", -1, &st, nullptr) !=
      SQLITE_OK) {
    err = sqlite3_errmsg(db);
    sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
    return false;
  }
  sqlite3_bind_int64(st, 1, id);
  std::string key;
  if (sqlite3_step(st) == SQLITE_ROW) key = ColText(st, 0);
  sqlite3_finalize(st);
  if (key.empty()) {
    sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
    err = "outbox id not found";
    return false;
  }
  sqlite3_stmt* ins = nullptr;
  sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO seen(dedupe_key, created_at) VALUES(?,?)", -1, &ins,
                     nullptr);
  sqlite3_bind_text(ins, 1, key.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(ins, 2, UnixNow());
  sqlite3_step(ins);
  sqlite3_finalize(ins);

  sqlite3_stmt* del = nullptr;
  sqlite3_prepare_v2(db, "DELETE FROM outbox WHERE id=?", -1, &del, nullptr);
  sqlite3_bind_int64(del, 1, id);
  bool ok = sqlite3_step(del) == SQLITE_DONE;
  if (!ok) err = sqlite3_errmsg(db);
  sqlite3_finalize(del);
  sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", nullptr, nullptr, nullptr);
  return ok;
}

bool Store::MarkOutboxFail(int64_t id, const std::string& error, int64_t next_attempt_at,
                           std::string& err) {
  sqlite3_stmt* st = nullptr;
  const char* sql =
      "UPDATE outbox SET attempts=attempts+1, last_error=?, next_attempt_at=? WHERE id=?";
  if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_), sql, -1, &st, nullptr) != SQLITE_OK) {
    err = sqlite3_errmsg(static_cast<sqlite3*>(db_));
    return false;
  }
  sqlite3_bind_text(st, 1, error.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 2, next_attempt_at);
  sqlite3_bind_int64(st, 3, id);
  bool ok = sqlite3_step(st) == SQLITE_DONE;
  if (!ok) err = sqlite3_errmsg(static_cast<sqlite3*>(db_));
  sqlite3_finalize(st);
  return ok;
}

bool Store::AbandonOutbox(int64_t id, const std::string& error, std::string& err) {
  // Mark seen so we don't re-enqueue same punch; drop from outbox.
  std::string e2;
  if (!MarkOutboxFail(id, error, UnixNow() + 365LL * 24 * 3600, e2)) {
    // still try to move to seen
  }
  return MarkOutboxOk(id, err);
}

int Store::Prune(int64_t older_than_unix, std::string& err) {
  sqlite3* db = static_cast<sqlite3*>(db_);
  int total = 0;
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db, "DELETE FROM seen WHERE created_at<?", -1, &st, nullptr) == SQLITE_OK) {
    sqlite3_bind_int64(st, 1, older_than_unix);
    if (sqlite3_step(st) == SQLITE_DONE) total += sqlite3_changes(db);
    else err = sqlite3_errmsg(db);
    sqlite3_finalize(st);
  }
  // Drop abandoned outbox (far-future next_attempt or very old)
  st = nullptr;
  if (sqlite3_prepare_v2(db, "DELETE FROM outbox WHERE created_at<?", -1, &st, nullptr) ==
      SQLITE_OK) {
    // Only prune rows that already exhausted retries (next far away) — keep active retries.
    // Safer: delete outbox older than retention AND attempts high — handled by caller abandoning.
    sqlite3_finalize(st);
  }
  // Prune exhausted: next_attempt_at more than 30 days out and created_at old
  st = nullptr;
  if (sqlite3_prepare_v2(
          db, "DELETE FROM outbox WHERE created_at<? AND next_attempt_at>?", -1, &st, nullptr) ==
      SQLITE_OK) {
    sqlite3_bind_int64(st, 1, older_than_unix);
    sqlite3_bind_int64(st, 2, UnixNow() + 30LL * 24 * 3600);
    if (sqlite3_step(st) == SQLITE_DONE) total += sqlite3_changes(db);
    sqlite3_finalize(st);
  }
  return total;
}

bool Store::SetMeta(const std::string& key, const std::string& value, std::string& err) {
  sqlite3_stmt* st = nullptr;
  const char* sql =
      "INSERT INTO meta(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value";
  if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_), sql, -1, &st, nullptr) != SQLITE_OK) {
    err = sqlite3_errmsg(static_cast<sqlite3*>(db_));
    return false;
  }
  sqlite3_bind_text(st, 1, key.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 2, value.c_str(), -1, SQLITE_TRANSIENT);
  bool ok = sqlite3_step(st) == SQLITE_DONE;
  if (!ok) err = sqlite3_errmsg(static_cast<sqlite3*>(db_));
  sqlite3_finalize(st);
  return ok;
}

bool Store::GetMeta(const std::string& key, std::string& value, std::string& err) {
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_), "SELECT value FROM meta WHERE key=?", -1, &st,
                         nullptr) != SQLITE_OK) {
    err = sqlite3_errmsg(static_cast<sqlite3*>(db_));
    return false;
  }
  sqlite3_bind_text(st, 1, key.c_str(), -1, SQLITE_TRANSIENT);
  bool ok = false;
  if (sqlite3_step(st) == SQLITE_ROW) {
    value = ColText(st, 0);
    ok = true;
  } else {
    err = "meta key not found";
  }
  sqlite3_finalize(st);
  return ok;
}

}  // namespace cg
