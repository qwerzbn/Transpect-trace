// Controlled protocol client for the Chromium Content Analysis SDK.
// This is not a browser substitute and must never be counted as normal-Chrome
// policy activation evidence.

#include <windows.h>
#include <fcntl.h>
#include <io.h>

#include <array>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "content_analysis/sdk/analysis_client.h"

namespace ca = content_analysis::sdk;

namespace {

enum class Mode { kUnset, kAttach, kBulk };

struct Config {
  Mode mode = Mode::kUnset;
  std::string value;
  std::string url = "https://chatgpt.com/";
  bool stdin_input = false;
};

constexpr size_t kMaxContentBytes = 1024u * 1024u;

bool Parse(int argc, char** argv, Config* config) {
  if (!config) return false;
  for (int index = 1; index < argc; ++index) {
    const std::string argument(argv[index]);
    constexpr char kMode[] = "--mode=";
    constexpr char kUrl[] = "--url=";
    if (argument.compare(0, sizeof(kMode) - 1, kMode) == 0) {
      const std::string value = argument.substr(sizeof(kMode) - 1);
      if (value == "attach") config->mode = Mode::kAttach;
      else if (value == "bulk") config->mode = Mode::kBulk;
      else return false;
    } else if (argument.compare(0, sizeof(kUrl) - 1, kUrl) == 0) {
      config->url = argument.substr(sizeof(kUrl) - 1);
    } else if (argument == "--stdin") {
      if (config->stdin_input) return false;
      config->stdin_input = true;
    } else if (config->value.empty() && !config->stdin_input) {
      config->value = argument;
    } else {
      return false;
    }
  }
  if (config->mode == Mode::kUnset || config->url.empty()) return false;
  if (config->mode == Mode::kAttach) {
    return !config->stdin_input && config->value.size() > 1 &&
           config->value[0] == '@';
  }
  return config->stdin_input ? config->value.empty()
                             : !config->value.empty() && config->value[0] != '@';
}

void Usage() {
  std::cerr << "Usage: ttrace-content-sdk-client --mode=attach|bulk "
            << "[--url=https://chatgpt.com/] [--stdin|@file-or-text]"
            << std::endl;
}

void Wipe(std::string* value) {
  if (value && !value->empty()) SecureZeroMemory(&(*value)[0], value->size());
}

bool ReadStdin(std::string* value) {
  if (!value || _setmode(_fileno(stdin), _O_BINARY) == -1) return false;
  std::array<char, 64u * 1024u> buffer{};
  while (true) {
    std::cin.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const std::streamsize count = std::cin.gcount();
    if (count < 0 ||
        static_cast<size_t>(count) > kMaxContentBytes - value->size()) {
      Wipe(value);
      SecureZeroMemory(buffer.data(), buffer.size());
      return false;
    }
    if (count == 0) break;
    value->append(buffer.data(), static_cast<size_t>(count));
  }
  SecureZeroMemory(buffer.data(), buffer.size());
  return !value->empty() && !std::cin.bad();
}

std::string UniqueId(const char* prefix) {
  std::ostringstream output;
  output << prefix << '-' << GetCurrentProcessId() << '-' << GetTickCount64();
  return output.str();
}

ca::ContentAnalysisRequest BuildRequest(const Config& config) {
  ca::ContentAnalysisRequest request;
  request.set_expires_at(std::time(nullptr) + 60);
  request.set_request_token(UniqueId("request"));
  request.set_user_action_id(UniqueId("action"));
  request.add_tags("dlp");
  request.mutable_request_data()->set_url(config.url);
  if (config.mode == Mode::kAttach) {
    request.set_analysis_connector(ca::FILE_ATTACHED);
    request.set_reason(ca::ContentAnalysisRequest::FILE_PICKER_DIALOG);
    request.set_file_path(config.value.substr(1));
  } else {
    request.set_analysis_connector(ca::BULK_DATA_ENTRY);
    request.set_reason(ca::ContentAnalysisRequest::CLIPBOARD_PASTE);
    request.set_text_content(config.value);
  }
  return request;
}

enum class Verdict { kAllow, kBlock, kFailure };

Verdict ReadVerdict(const ca::ContentAnalysisResponse& response) {
  if (response.results_size() == 0) return Verdict::kFailure;
  bool saw_success = false;
  for (const auto& result : response.results()) {
    if (!result.has_status() ||
        result.status() != ca::ContentAnalysisResponse::Result::SUCCESS) {
      return Verdict::kFailure;
    }
    saw_success = true;
    for (const auto& rule : result.triggered_rules()) {
      if (!rule.has_action()) return Verdict::kFailure;
      if (rule.action() ==
          ca::ContentAnalysisResponse::Result::TriggeredRule::BLOCK) {
        return Verdict::kBlock;
      }
      // The controlled policy contract is deliberately binary.  REPORT_ONLY,
      // WARN and unspecified rules are not silently interpreted as ALLOW.
      return Verdict::kFailure;
    }
  }
  return saw_success ? Verdict::kAllow : Verdict::kFailure;
}

const char* VerdictName(Verdict verdict) {
  switch (verdict) {
    case Verdict::kAllow: return "ALLOW";
    case Verdict::kBlock: return "BLOCK";
    case Verdict::kFailure: return "FAILURE";
  }
  return "FAILURE";
}

}  // namespace

int main(int argc, char** argv) {
  Config config{};
  if (!Parse(argc, argv, &config)) {
    Usage();
    return 2;
  }
  if (config.stdin_input && !ReadStdin(&config.value)) {
    std::cout << "{\"event\":\"stdin_invalid_or_too_large\"}" << std::endl;
    return 2;
  }
  auto client = ca::Client::Create({"path_user", true});
  if (!client) {
    Wipe(&config.value);
    std::cout << "{\"event\":\"client_start_failed\"}" << std::endl;
    return 3;
  }
  ca::ContentAnalysisRequest request = BuildRequest(config);
  Wipe(&config.value);
  ca::ContentAnalysisResponse response;
  const int send_result = client->Send(request, &response);
  if (request.has_text_content()) Wipe(request.mutable_text_content());
  if (request.has_file_path()) Wipe(request.mutable_file_path());
  if (send_result != 0 || response.request_token() != request.request_token()) {
    std::cout << "{\"event\":\"transport_failed\"}" << std::endl;
    return 4;
  }
  const Verdict verdict = ReadVerdict(response);
  ca::ContentAnalysisAcknowledgement acknowledgement;
  acknowledgement.set_request_token(request.request_token());
  acknowledgement.set_status(ca::ContentAnalysisAcknowledgement::SUCCESS);
  acknowledgement.set_final_action(
      verdict == Verdict::kAllow
          ? ca::ContentAnalysisAcknowledgement::ALLOW
          : ca::ContentAnalysisAcknowledgement::BLOCK);
  if (client->Acknowledge(acknowledgement) != 0) {
    std::cout << "{\"event\":\"acknowledgement_failed\"}" << std::endl;
    return 5;
  }
  std::cout << "{\"event\":\"result\",\"decision\":\""
            << VerdictName(verdict) << "\"}" << std::endl;
  if (verdict == Verdict::kAllow) return 0;
  if (verdict == Verdict::kBlock) return 10;
  return 11;
}
