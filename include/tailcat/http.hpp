#pragma once

#include <map>
#include <string>
#include <string_view>

namespace tailcat {

struct HttpResponse {
  int status = 0;
  std::string body;
  std::map<std::string, std::string> headers;
};

HttpResponse https_get(std::string_view url,
                       const std::map<std::string, std::string>& headers = {});

}  // namespace tailcat
