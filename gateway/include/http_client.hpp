#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace cg {

struct HttpResponse {
  long status = 0;
  std::string body;
  std::string error;
};

class HttpClient {
 public:
  explicit HttpClient(int timeout_sec = 30);
  ~HttpClient();

  HttpResponse Request(const std::string& method, const std::string& url,
                       const std::string& body,
                       const std::map<std::string, std::string>& headers) const;

 private:
  int timeout_sec_;
};

}  // namespace cg
