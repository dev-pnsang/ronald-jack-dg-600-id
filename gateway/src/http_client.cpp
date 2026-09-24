#include "http_client.hpp"

#include <curl/curl.h>

namespace cg {
namespace {

size_t WriteCb(char* ptr, size_t size, size_t nmemb, void* userdata) {
  auto* out = static_cast<std::string*>(userdata);
  out->append(ptr, size * nmemb);
  return size * nmemb;
}

}  // namespace

HttpClient::HttpClient(int timeout_sec) : timeout_sec_(timeout_sec) {
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

HttpClient::~HttpClient() { curl_global_cleanup(); }

HttpResponse HttpClient::Request(const std::string& method, const std::string& url,
                                 const std::string& body,
                                 const std::map<std::string, std::string>& headers) const {
  HttpResponse resp;
  CURL* curl = curl_easy_init();
  if (!curl) {
    resp.error = "curl_easy_init failed";
    return resp;
  }

  struct curl_slist* hdrs = nullptr;
  for (const auto& kv : headers) {
    std::string line = kv.first + ": " + kv.second;
    hdrs = curl_slist_append(hdrs, line.c_str());
  }

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp.body);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>(timeout_sec_));
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "checkin-gateway/1.0");

  if (method != "GET" && method != "HEAD") {
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
  }

  CURLcode rc = curl_easy_perform(curl);
  if (rc != CURLE_OK) {
    resp.error = curl_easy_strerror(rc);
  } else {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp.status);
  }

  curl_slist_free_all(hdrs);
  curl_easy_cleanup(curl);
  return resp;
}

}  // namespace cg
