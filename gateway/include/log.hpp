#pragma once

#include <cstdio>
#include <string>

namespace cg {

enum class LogLevel { Debug = 0, Info = 1, Warning = 2, Error = 3 };

inline LogLevel& GlobalLogLevel() {
  static LogLevel level = LogLevel::Info;
  return level;
}

inline const char* LogLevelName(LogLevel l) {
  switch (l) {
    case LogLevel::Debug: return "DEBUG";
    case LogLevel::Info: return "INFO";
    case LogLevel::Warning: return "WARNING";
    case LogLevel::Error: return "ERROR";
  }
  return "INFO";
}

inline void Log(LogLevel level, const std::string& msg) {
  if (static_cast<int>(level) < static_cast<int>(GlobalLogLevel())) return;
  std::fprintf(stderr, "[%s] %s\n", LogLevelName(level), msg.c_str());
  std::fflush(stderr);
}

inline void LogDebug(const std::string& msg) { Log(LogLevel::Debug, msg); }
inline void LogInfo(const std::string& msg) { Log(LogLevel::Info, msg); }
inline void LogWarning(const std::string& msg) { Log(LogLevel::Warning, msg); }
inline void LogError(const std::string& msg) { Log(LogLevel::Error, msg); }

}  // namespace cg
