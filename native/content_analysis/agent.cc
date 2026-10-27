// Windows Chrome Content Analysis Agent prototype.
//
// This executable uses Chromium's official Content Analysis SDK.  It does not
// modify Chrome, terminate Chrome, intercept TLS, or log inspected content.

#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <deque>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#define JSMN_STATIC
#define JSMN_STRICT
#define JSMN_PARENT_LINKS
#include "jsmn.h"

#include "content_analysis/sdk/analysis_agent.h"

namespace ca = content_analysis::sdk;

namespace {

constexpr size_t kMaxContentBytes = 1024u * 1024u;
constexpr DWORD kMaxPolicyReply = 64u * 1024u;
constexpr size_t kMaxQueueDepth = 32u;
constexpr unsigned kWorkerCount = 5u;
constexpr DWORD kDefaultPolicyTimeoutMs = 2000u;
constexpr char kRequestSchema[] = "transpect.chrome.content.request/1.0";
constexpr char kReplySchema[] = "transpect.chrome.content.reply/1.0";
constexpr char kSdkChannel[] = "path_user";

struct ScopedHandle {
  HANDLE value = INVALID_HANDLE_VALUE;
  ScopedHandle() = default;
  explicit ScopedHandle(HANDLE handle) : value(handle) {}
  ~ScopedHandle() {
    if (value != INVALID_HANDLE_VALUE && value != nullptr) CloseHandle(value);
  }
  ScopedHandle(const ScopedHandle&) = delete;
  ScopedHandle& operator=(const ScopedHandle&) = delete;
  ScopedHandle(ScopedHandle&& other) noexcept : value(other.value) {
    other.value = INVALID_HANDLE_VALUE;
  }
  ScopedHandle& operator=(ScopedHandle&& other) noexcept {
    if (this != &other) {
      if (value != INVALID_HANDLE_VALUE && value != nullptr) CloseHandle(value);
      value = other.value;
      other.value = INVALID_HANDLE_VALUE;
    }
    return *this;
  }
  explicit operator bool() const {
    return value != INVALID_HANDLE_VALUE && value != nullptr;
  }
};

struct ProcessIdentity {
  std::wstring image;
  uint64_t creation_time = 0;
  std::string image_sha256;
};

struct Config {
  std::wstring policy_pipe;
  DWORD policy_pid = 0;
  std::wstring allowed_browser_path;
  DWORD timeout_ms = kDefaultPolicyTimeoutMs;
  bool sdk_test_client = false;
  ProcessIdentity policy_identity;
  std::string allowed_browser_sha256;
};

struct FileIdentity {
  FILE_ID_128 id{};
  DWORD volume_serial = 0;
  LARGE_INTEGER size{};
  LARGE_INTEGER write_time{};
};

struct WorkItem {
  std::unique_ptr<ca::ContentAnalysisEvent> event;
  std::string action_hash;
};

std::mutex g_output_mutex;
std::atomic<ca::Agent*> g_agent(nullptr);

void Audit(const std::string& event, const std::string& detail = std::string()) {
  std::lock_guard<std::mutex> lock(g_output_mutex);
  std::cout << "{\"component\":\"content_analysis_agent\",\"event\":\""
            << event << "\"";
  if (!detail.empty()) std::cout << "," << detail;
  std::cout << "}" << std::endl;
}

std::wstring Utf8ToWide(const std::string& input) {
  if (input.empty()) return std::wstring();
  const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                        input.data(),
                                        static_cast<int>(input.size()), nullptr, 0);
  if (count <= 0) return std::wstring();
  std::wstring output(static_cast<size_t>(count), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                          static_cast<int>(input.size()), &output[0], count) != count) {
    return std::wstring();
  }
  return output;
}

std::string WideToUtf8(const std::wstring& input) {
  if (input.empty()) return std::string();
  const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                        input.data(),
                                        static_cast<int>(input.size()), nullptr, 0,
                                        nullptr, nullptr);
  if (count <= 0) return std::string();
  std::string output(static_cast<size_t>(count), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(),
                          static_cast<int>(input.size()), &output[0], count,
                          nullptr, nullptr) != count) {
    return std::string();
  }
  return output;
}

std::wstring NormalizePath(const std::wstring& value) {
  if (value.empty()) return std::wstring();
  std::array<wchar_t, 32768> buffer{};
  const DWORD count = GetFullPathNameW(value.c_str(),
                                       static_cast<DWORD>(buffer.size()),
                                       buffer.data(), nullptr);
  if (count == 0 || count >= static_cast<DWORD>(buffer.size()))
    return std::wstring();
  std::wstring result(buffer.data(), count);
  std::transform(result.begin(), result.end(), result.begin(),
                 [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
  return result;
}

uint64_t FileTimeValue(const FILETIME& value) {
  ULARGE_INTEGER combined{};
  combined.LowPart = value.dwLowDateTime;
  combined.HighPart = value.dwHighDateTime;
  return combined.QuadPart;
}

bool QueryProcessIdentity(DWORD pid, ProcessIdentity* identity) {
  if (!identity) return false;
  ScopedHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                   FALSE, pid));
  if (!process) return false;
  std::array<wchar_t, 32768> image{};
  DWORD image_size = static_cast<DWORD>(image.size());
  FILETIME created{}, exited{}, kernel{}, user{};
  if (!QueryFullProcessImageNameW(process.value, 0, image.data(), &image_size) ||
      !GetProcessTimes(process.value, &created, &exited, &kernel, &user)) {
    return false;
  }
  identity->image = NormalizePath(std::wstring(image.data(), image_size));
  identity->creation_time = FileTimeValue(created);
  return !identity->image.empty();
}

bool EqualFileIdentity(const FileIdentity& lhs, const FileIdentity& rhs) {
  return lhs.volume_serial == rhs.volume_serial &&
         std::memcmp(&lhs.id, &rhs.id, sizeof(lhs.id)) == 0 &&
         lhs.size.QuadPart == rhs.size.QuadPart &&
         lhs.write_time.QuadPart == rhs.write_time.QuadPart;
}

bool QueryFileIdentity(HANDLE file, FileIdentity* identity) {
  if (!identity) return false;
  FILE_ID_INFO id_info{};
  FILE_STANDARD_INFO standard{};
  FILE_BASIC_INFO basic{};
  BY_HANDLE_FILE_INFORMATION legacy{};
  if (!GetFileInformationByHandleEx(file, FileIdInfo, &id_info, sizeof(id_info)) ||
      !GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard)) ||
      !GetFileInformationByHandleEx(file, FileBasicInfo, &basic, sizeof(basic)) ||
      !GetFileInformationByHandle(file, &legacy)) {
    return false;
  }
  identity->id = id_info.FileId;
  identity->volume_serial = legacy.dwVolumeSerialNumber;
  identity->size = standard.EndOfFile;
  identity->write_time = basic.LastWriteTime;
  return !standard.Directory;
}

bool SnapshotFile(const std::string& utf8_path, std::vector<uint8_t>* bytes,
                  ScopedHandle* held_file, std::string* limitation) {
  if (!bytes || !held_file || !limitation) return false;
  const std::wstring path = Utf8ToWide(utf8_path);
  if (path.empty()) {
    *limitation = "invalid_file_path";
    return false;
  }
  ScopedHandle file(CreateFileW(
      path.c_str(), FILE_READ_DATA | FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ, nullptr, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
          FILE_FLAG_SEQUENTIAL_SCAN,
      nullptr));
  if (!file) {
    *limitation = "file_open_failed";
    return false;
  }
  FILE_ATTRIBUTE_TAG_INFO tag{};
  if (!GetFileInformationByHandleEx(file.value, FileAttributeTagInfo, &tag,
                                    sizeof(tag)) ||
      (tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT |
                             FILE_ATTRIBUTE_DIRECTORY)) != 0) {
    *limitation = "unsupported_file_identity";
    return false;
  }
  FileIdentity before{};
  if (!QueryFileIdentity(file.value, &before) || before.size.QuadPart < 0 ||
      static_cast<uint64_t>(before.size.QuadPart) > kMaxContentBytes) {
    *limitation = "file_identity_or_size_invalid";
    return false;
  }
  bytes->assign(static_cast<size_t>(before.size.QuadPart), 0);
  size_t offset = 0;
  while (offset < bytes->size()) {
    DWORD read = 0;
    const DWORD wanted = static_cast<DWORD>(bytes->size() - offset);
    if (!ReadFile(file.value, bytes->data() + offset, wanted, &read, nullptr) ||
        read == 0) {
      *limitation = "file_read_failed";
      return false;
    }
    offset += static_cast<size_t>(read);
  }
  uint8_t extra = 0;
  DWORD extra_read = 0;
  if (!ReadFile(file.value, &extra, 1, &extra_read, nullptr) || extra_read != 0) {
    *limitation = "file_changed_during_read";
    return false;
  }
  FileIdentity after{};
  if (!QueryFileIdentity(file.value, &after) || !EqualFileIdentity(before, after)) {
    *limitation = "file_changed_during_read";
    return false;
  }
  *held_file = std::move(file);
  return true;
}

std::string JsonEscape(const std::string& input) {
  std::ostringstream out;
  for (unsigned char c : input) {
    switch (c) {
      case '\\': out << "\\\\"; break;
      case '"': out << "\\\""; break;
      case '\b': out << "\\b"; break;
      case '\f': out << "\\f"; break;
      case '\n': out << "\\n"; break;
      case '\r': out << "\\r"; break;
      case '\t': out << "\\t"; break;
      default:
        if (c < 0x20) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<unsigned>(c) << std::dec;
        } else {
          out << static_cast<char>(c);
        }
    }
  }
  return out.str();
}

void Wipe(std::vector<uint8_t>* bytes) {
  if (bytes && !bytes->empty()) SecureZeroMemory(bytes->data(), bytes->size());
}

bool IsUtf8(const std::vector<uint8_t>& bytes) {
  size_t index = 0;
  while (index < bytes.size()) {
    const uint8_t first = bytes[index++];
    if (first <= 0x7f) continue;
    uint32_t codepoint = 0;
    size_t continuation = 0;
    uint32_t minimum = 0;
    if ((first & 0xe0u) == 0xc0u) {
      codepoint = first & 0x1fu;
      continuation = 1;
      minimum = 0x80u;
    } else if ((first & 0xf0u) == 0xe0u) {
      codepoint = first & 0x0fu;
      continuation = 2;
      minimum = 0x800u;
    } else if ((first & 0xf8u) == 0xf0u) {
      codepoint = first & 0x07u;
      continuation = 3;
      minimum = 0x10000u;
    } else {
      return false;
    }
    if (continuation > bytes.size() - index) return false;
    for (size_t count = 0; count < continuation; ++count) {
      const uint8_t next = bytes[index++];
      if ((next & 0xc0u) != 0x80u) return false;
      codepoint = (codepoint << 6u) | (next & 0x3fu);
    }
    if (codepoint < minimum || codepoint > 0x10ffffu ||
        (codepoint >= 0xd800u && codepoint <= 0xdfffu)) {
      return false;
    }
  }
  return true;
}

std::string Sha256Hex(const void* value, size_t value_size) {
  if (value_size > MAXDWORD) return std::string();
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD object_size = 0;
  DWORD written = 0;
  std::vector<uint8_t> object;
  std::array<uint8_t, 32> digest{};
  bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                         nullptr, 0) == 0;
  if (ok) {
    ok = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                           reinterpret_cast<PUCHAR>(&object_size),
                           sizeof(object_size), &written, 0) == 0;
  }
  if (ok) {
    object.resize(object_size);
    ok = BCryptCreateHash(algorithm, &hash, object.data(), object_size,
                          nullptr, 0, 0) == 0;
  }
  if (ok && value_size != 0) {
    ok = BCryptHashData(hash,
                        reinterpret_cast<PUCHAR>(const_cast<void*>(value)),
                        static_cast<ULONG>(value_size), 0) == 0;
  }
  if (ok) {
    ok = BCryptFinishHash(hash, digest.data(),
                          static_cast<ULONG>(digest.size()), 0) == 0;
  }
  if (hash) BCryptDestroyHash(hash);
  if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
  if (!ok) return std::string();
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (uint8_t byte : digest) out << std::setw(2) << static_cast<unsigned>(byte);
  return out.str();
}

std::string Sha256Hex(const std::string& value) {
  return Sha256Hex(value.data(), value.size());
}

std::string Sha256Hex(const std::vector<uint8_t>& value) {
  return Sha256Hex(value.data(), value.size());
}

std::string Sha256File(const std::wstring& path) {
  ScopedHandle file(CreateFileW(path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                                nullptr));
  if (!file) return std::string();
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD object_size = 0;
  DWORD written = 0;
  std::vector<uint8_t> object;
  std::array<uint8_t, 32> digest{};
  bool ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                         nullptr, 0) == 0;
  if (ok) {
    ok = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                           reinterpret_cast<PUCHAR>(&object_size),
                           sizeof(object_size), &written, 0) == 0;
  }
  if (ok) {
    object.resize(object_size);
    ok = BCryptCreateHash(algorithm, &hash, object.data(), object_size,
                          nullptr, 0, 0) == 0;
  }
  std::vector<uint8_t> buffer(64u * 1024u, 0);
  while (ok) {
    DWORD count = 0;
    if (!ReadFile(file.value, buffer.data(), static_cast<DWORD>(buffer.size()),
                  &count, nullptr)) {
      ok = false;
      break;
    }
    if (count == 0) break;
    ok = BCryptHashData(hash, buffer.data(), count, 0) == 0;
  }
  SecureZeroMemory(buffer.data(), buffer.size());
  if (ok) {
    ok = BCryptFinishHash(hash, digest.data(),
                          static_cast<ULONG>(digest.size()), 0) == 0;
  }
  if (hash) BCryptDestroyHash(hash);
  if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
  if (!ok) return std::string();
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (uint8_t byte : digest) out << std::setw(2) << static_cast<unsigned>(byte);
  return out.str();
}

std::string DestinationHost(const std::string& url) {
  if (url.empty() || url.size() > 8192u) return std::string();
  const std::wstring wide = Utf8ToWide(url);
  if (wide.empty()) return std::string();
  URL_COMPONENTS parts{};
  parts.dwStructSize = sizeof(parts);
  parts.dwHostNameLength = static_cast<DWORD>(-1);
  parts.dwSchemeLength = static_cast<DWORD>(-1);
  if (!WinHttpCrackUrl(wide.c_str(), static_cast<DWORD>(wide.size()), 0, &parts) ||
      !parts.lpszHostName || parts.dwHostNameLength == 0 ||
      (parts.nScheme != INTERNET_SCHEME_HTTP &&
       parts.nScheme != INTERNET_SCHEME_HTTPS)) {
    return std::string();
  }
  std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
  std::transform(host.begin(), host.end(), host.begin(),
                 [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
  const bool default_port =
      (parts.nScheme == INTERNET_SCHEME_HTTP && parts.nPort == 80) ||
      (parts.nScheme == INTERNET_SCHEME_HTTPS && parts.nPort == 443);
  if (!default_port) host += L":" + std::to_wstring(parts.nPort);
  return WideToUtf8(host);
}

std::string ConnectorName(const ca::ContentAnalysisRequest& request) {
  if (!request.has_analysis_connector()) return "UNKNOWN";
  switch (request.analysis_connector()) {
    case ca::FILE_ATTACHED: return "FILE_ATTACHED";
    case ca::BULK_DATA_ENTRY: return "BULK_DATA_ENTRY";
    default: return "UNKNOWN";
  }
}

std::string ReasonName(const ca::ContentAnalysisRequest& request) {
  if (!request.has_reason()) return "UNKNOWN";
  switch (request.reason()) {
    case ca::ContentAnalysisRequest::CLIPBOARD_PASTE: return "CLIPBOARD_PASTE";
    case ca::ContentAnalysisRequest::DRAG_AND_DROP: return "DRAG_AND_DROP";
    case ca::ContentAnalysisRequest::FILE_PICKER_DIALOG: return "FILE_PICKER_DIALOG";
    default: return "UNKNOWN";
  }
}

bool Transfer(HANDLE pipe, void* buffer, DWORD size, bool writing,
              ULONGLONG deadline) {
  DWORD offset = 0;
  while (offset < size) {
    const ULONGLONG now = GetTickCount64();
    if (now >= deadline) return false;
    ScopedHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return false;
    OVERLAPPED overlapped{};
    overlapped.hEvent = event.value;
    DWORD transferred = 0;
    BOOL ok = writing
                  ? WriteFile(pipe, static_cast<uint8_t*>(buffer) + offset,
                              size - offset, &transferred, &overlapped)
                  : ReadFile(pipe, static_cast<uint8_t*>(buffer) + offset,
                             size - offset, &transferred, &overlapped);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
      const DWORD remaining = static_cast<DWORD>(deadline - now);
      if (WaitForSingleObject(event.value, remaining) == WAIT_OBJECT_0) {
        ok = GetOverlappedResult(pipe, &overlapped, &transferred, FALSE);
      } else {
        CancelIoEx(pipe, &overlapped);
        GetOverlappedResult(pipe, &overlapped, &transferred, TRUE);
        ok = FALSE;
      }
    }
    if (!ok || transferred == 0) return false;
    offset += transferred;
  }
  return true;
}

bool JsonField(const std::string& json, const jsmntok_t* tokens, int count,
               const char* key, std::string* value) {
  int found = 0;
  for (int index = 1; index + 1 < count; ++index) {
    const jsmntok_t& token = tokens[index];
    if (token.parent != 0 || token.type != JSMN_STRING) continue;
    const int key_size = token.end - token.start;
    if (key_size != static_cast<int>(std::strlen(key)) ||
        std::memcmp(json.data() + token.start, key,
                    static_cast<size_t>(key_size)) != 0) {
      continue;
    }
    const jsmntok_t& content = tokens[index + 1];
    if (++found != 1 || content.parent != index || content.type != JSMN_STRING)
      return false;
    value->assign(json.data() + content.start,
                  static_cast<size_t>(content.end - content.start));
  }
  return found == 1;
}

bool ParseAllowReply(const std::string& reply,
                     const std::string& expected_attempt_id) {
  jsmn_parser parser{};
  jsmn_init(&parser);
  std::array<jsmntok_t, 96> tokens{};
  const int count = jsmn_parse(&parser, reply.data(), reply.size(),
                               tokens.data(),
                               static_cast<unsigned int>(tokens.size()));
  if (count < 1 || tokens[0].type != JSMN_OBJECT) return false;
  std::string schema;
  std::string attempt_id;
  std::string decision;
  std::string action;
  if (!JsonField(reply, tokens.data(), count, "schema_version", &schema) ||
      !JsonField(reply, tokens.data(), count, "attempt_id", &attempt_id) ||
      !JsonField(reply, tokens.data(), count, "decision", &decision) ||
      !JsonField(reply, tokens.data(), count, "action", &action)) {
    return false;
  }
  return schema == kReplySchema && attempt_id == expected_attempt_id &&
         decision == "ALLOW" && action == "allow";
}

enum class PolicyResult { kAllow, kBlock, kFailure };

PolicyResult QueryPolicy(const Config& config, const std::string& header,
                         const std::vector<uint8_t>& body,
                         const std::string& expected_attempt_id) {
  ULONGLONG deadline = GetTickCount64() + config.timeout_ms;
  HANDLE raw_pipe = INVALID_HANDLE_VALUE;
  do {
    raw_pipe = CreateFileW(config.policy_pipe.c_str(),
                           GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (raw_pipe != INVALID_HANDLE_VALUE || GetLastError() != ERROR_PIPE_BUSY)
      break;
    const ULONGLONG now = GetTickCount64();
    if (now >= deadline ||
        !WaitNamedPipeW(config.policy_pipe.c_str(),
                        static_cast<DWORD>(deadline - now))) {
      break;
    }
  } while (GetTickCount64() < deadline);
  ScopedHandle pipe(raw_pipe);
  if (!pipe) return PolicyResult::kFailure;
  ULONG server_pid = 0;
  if (!GetNamedPipeServerProcessId(pipe.value, &server_pid) ||
      server_pid != config.policy_pid) {
    return PolicyResult::kFailure;
  }
  ProcessIdentity policy_identity{};
  if (!QueryProcessIdentity(server_pid, &policy_identity) ||
      policy_identity.creation_time != config.policy_identity.creation_time ||
      policy_identity.image != config.policy_identity.image) {
    return PolicyResult::kFailure;
  }
  uint32_t header_size = static_cast<uint32_t>(header.size());
  if (!Transfer(pipe.value, &header_size, sizeof(header_size),
                true, deadline) ||
      !Transfer(pipe.value, const_cast<char*>(header.data()), header_size, true,
                deadline) ||
      (!body.empty() &&
       !Transfer(pipe.value, const_cast<uint8_t*>(body.data()),
                 static_cast<DWORD>(body.size()), true,
                 deadline))) {
    return PolicyResult::kFailure;
  }
  uint32_t reply_size = 0;
  if (!Transfer(pipe.value, &reply_size, sizeof(reply_size), false, deadline) ||
      reply_size == 0 || reply_size > kMaxPolicyReply) {
    return PolicyResult::kFailure;
  }
  std::string reply(reply_size, '\0');
  if (!Transfer(pipe.value, &reply[0], reply_size, false, deadline))
    return PolicyResult::kFailure;
  if (ParseAllowReply(reply, expected_attempt_id)) return PolicyResult::kAllow;

  // A syntactically valid BLOCK response and all UNKNOWN/invalid responses
  // fail closed.  Only the explicit ALLOW tuple can authorize use.
  jsmn_parser parser{};
  jsmn_init(&parser);
  std::array<jsmntok_t, 96> tokens{};
  const int count = jsmn_parse(&parser, reply.data(), reply.size(),
                               tokens.data(),
                               static_cast<unsigned int>(tokens.size()));
  std::string schema;
  std::string attempt_id;
  std::string decision;
  std::string action;
  if (count > 0 && JsonField(reply, tokens.data(), count, "schema_version", &schema) &&
      JsonField(reply, tokens.data(), count, "attempt_id", &attempt_id) &&
      JsonField(reply, tokens.data(), count, "decision", &decision) &&
      JsonField(reply, tokens.data(), count, "action", &action) &&
      schema == kReplySchema && attempt_id == expected_attempt_id &&
      decision == "BLOCK" && action == "block") {
    return PolicyResult::kBlock;
  }
  return PolicyResult::kFailure;
}

std::string TagsJson(const ca::ContentAnalysisRequest& request) {
  std::ostringstream out;
  out << '[';
  for (int index = 0; index < request.tags_size(); ++index) {
    if (index) out << ',';
    out << '"' << JsonEscape(request.tags(index)) << '"';
  }
  out << ']';
  return out.str();
}

bool ValidTags(const ca::ContentAnalysisRequest& request) {
  if (request.tags_size() > 16) return false;
  for (int index = 0; index < request.tags_size(); ++index) {
    const std::string& tag = request.tags(index);
    if (tag.empty() || tag.size() > 64u) return false;
    for (const unsigned char value : tag) {
      if (!((value >= 'a' && value <= 'z') ||
            (value >= 'A' && value <= 'Z') ||
            (value >= '0' && value <= '9') || value == '_' || value == '.' ||
            value == ':' || value == '-')) {
        return false;
      }
    }
  }
  return true;
}

std::string BuildPolicyHeader(const ca::ContentAnalysisRequest& request,
                              const std::string& destination_host,
                              const std::string& connector,
                              const std::string& reason,
                              const std::string& request_token_sha256,
                              const std::string& user_action_id_sha256,
                              const std::string& body_sha256,
                              size_t body_size) {
  std::ostringstream out;
  out << "{\"schema_version\":\"" << kRequestSchema << "\""
      << ",\"attempt_id\":\"" << request_token_sha256 << "\""
      << ",\"connector\":\"" << connector << "\""
      << ",\"reason\":\"" << reason << "\""
      << ",\"destination_host\":\"" << JsonEscape(destination_host) << "\""
      << ",\"completeness\":\"complete\""
      << ",\"encoding_state\":\"utf8\""
      << ",\"body_sha256\":\"" << body_sha256 << "\""
      << ",\"body_bytes\":" << body_size
      << ",\"request_token_sha256\":\"" << request_token_sha256 << "\""
      << ",\"user_action_id_sha256\":";
  if (user_action_id_sha256.empty()) {
    out << "null";
  } else {
    out << '"' << user_action_id_sha256 << '"';
  }
  out << ",\"expires_at\":" << request.expires_at()
      << ",\"tags\":" << TagsJson(request)
      << ",\"limitations\":[]}";
  return out.str();
}

std::string AckStatus(const ca::ContentAnalysisAcknowledgement& ack) {
  if (!ack.has_status()) return "UNKNOWN";
  switch (ack.status()) {
    case ca::ContentAnalysisAcknowledgement::SUCCESS: return "SUCCESS";
    case ca::ContentAnalysisAcknowledgement::INVALID_RESPONSE: return "INVALID_RESPONSE";
    case ca::ContentAnalysisAcknowledgement::TOO_LATE: return "TOO_LATE";
    default: return "UNKNOWN";
  }
}

std::string AckAction(const ca::ContentAnalysisAcknowledgement& ack) {
  if (!ack.has_final_action()) return "UNKNOWN";
  switch (ack.final_action()) {
    case ca::ContentAnalysisAcknowledgement::ALLOW: return "ALLOW";
    case ca::ContentAnalysisAcknowledgement::REPORT_ONLY: return "REPORT_ONLY";
    case ca::ContentAnalysisAcknowledgement::WARN: return "WARN";
    case ca::ContentAnalysisAcknowledgement::BLOCK: return "BLOCK";
    default: return "UNKNOWN";
  }
}

class Handler final : public ca::AgentEventHandler {
 public:
  explicit Handler(Config config) : config_(std::move(config)) {
    for (unsigned index = 0; index < kWorkerCount; ++index)
      workers_.emplace_back(&Handler::Worker, this);
  }

  ~Handler() override {
    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      stopping_ = true;
    }
    queue_ready_.notify_all();
    for (auto& worker : workers_) worker.join();
  }

 private:
  void OnBrowserConnected(const ca::BrowserInfo& info) override {
    ProcessIdentity identity{};
    const std::wstring reported = NormalizePath(Utf8ToWide(info.binary_path));
    const bool actual_ok = QueryProcessIdentity(info.pid, &identity);
    if (actual_ok) identity.image_sha256 = Sha256File(identity.image);
    const bool path_ok = actual_ok && reported == identity.image &&
                         identity.image == config_.allowed_browser_path &&
                         !identity.image_sha256.empty() &&
                         identity.image_sha256 == config_.allowed_browser_sha256;
    const bool chrome_name = identity.image.size() >= 10 &&
        identity.image.compare(identity.image.size() - 10, 10, L"chrome.exe") == 0;
    // Test mode still requires the exact configured path and immutable hash;
    // it only relaxes the production executable basename check.
    const bool test_name = config_.sdk_test_client;
    const bool basename_ok = chrome_name || test_name;
    if (path_ok && basename_ok) {
      std::lock_guard<std::mutex> lock(browser_mutex_);
      browsers_[info.pid] = identity;
    }
    Audit("browser_connected",
          "\"pid\":" + std::to_string(info.pid) +
              ",\"trusted\":" + (path_ok && basename_ok ? "true" : "false") +
              ",\"test_mode\":" + (config_.sdk_test_client ? "true" : "false"));
  }

  void OnBrowserDisconnected(const ca::BrowserInfo& info) override {
    {
      std::lock_guard<std::mutex> lock(browser_mutex_);
      browsers_.erase(info.pid);
    }
    Audit("browser_disconnected", "\"pid\":" + std::to_string(info.pid));
  }

  void OnAnalysisRequested(
      std::unique_ptr<ca::ContentAnalysisEvent> event) override {
    const std::string action_hash = event->GetRequest().has_user_action_id()
        ? Sha256Hex(event->GetRequest().user_action_id())
        : std::string();
    bool queued = false;
    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      if (!stopping_ && queue_.size() < kMaxQueueDepth) {
        WorkItem item;
        item.event = std::move(event);
        item.action_hash = action_hash;
        queue_.push_back(std::move(item));
        queued = true;
      }
    }
    if (queued) {
      queue_ready_.notify_one();
      return;
    }
    SendFailure(std::move(event), "queue_unavailable");
  }

  void OnResponseAcknowledged(
      const ca::ContentAnalysisAcknowledgement& ack) override {
    Audit("response_acknowledged",
          "\"request_token_sha256\":\"" + Sha256Hex(ack.request_token()) +
              "\",\"status\":\"" + AckStatus(ack) +
              "\",\"final_action\":\"" + AckAction(ack) + "\"");
  }

  void OnCancelRequests(
      const ca::ContentAnalysisCancelRequests& cancel) override {
    const std::string hash = Sha256Hex(cancel.user_action_id());
    {
      std::lock_guard<std::mutex> lock(cancel_mutex_);
      cancelled_actions_[hash] = GetTickCount64();
    }
    Audit("requests_cancelled", "\"user_action_id_sha256\":\"" + hash + "\"");
  }

  void OnInternalError(const char* context, ca::ResultCode error) override {
    (void)context;  // SDK context can contain implementation detail; do not persist it.
    Audit("sdk_internal_error",
          "\"result_code\":\"" +
              JsonEscape(ca::ResultCodeToString(error)) + "\"");
  }

  bool IsCancelled(const std::string& action_hash) {
    if (action_hash.empty()) return false;
    std::lock_guard<std::mutex> lock(cancel_mutex_);
    const ULONGLONG now = GetTickCount64();
    for (auto item = cancelled_actions_.begin(); item != cancelled_actions_.end();) {
      if (now - item->second > 10u * 60u * 1000u) {
        item = cancelled_actions_.erase(item);
      } else {
        ++item;
      }
    }
    return cancelled_actions_.find(action_hash) != cancelled_actions_.end();
  }

  bool BrowserAllowed(const ca::BrowserInfo& info) {
    ProcessIdentity current{};
    if (!QueryProcessIdentity(info.pid, &current)) return false;
    current.image_sha256 = Sha256File(current.image);
    std::lock_guard<std::mutex> lock(browser_mutex_);
    const auto found = browsers_.find(info.pid);
    return found != browsers_.end() &&
           found->second.creation_time == current.creation_time &&
           found->second.image == current.image &&
           !current.image_sha256.empty() &&
           found->second.image_sha256 == current.image_sha256 &&
           current.image_sha256 == config_.allowed_browser_sha256;
  }

  void Worker() {
    while (true) {
      WorkItem item;
      {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        queue_ready_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
        if (queue_.empty()) {
          if (stopping_) return;
          continue;
        }
        item = std::move(queue_.front());
        queue_.pop_front();
      }
      Process(std::move(item));
    }
  }

  void Process(WorkItem item) {
    auto& event = item.event;
    const ca::ContentAnalysisRequest& request = event->GetRequest();
    const std::string token_hash = Sha256Hex(request.request_token());
    if (request.request_token().empty() || request.request_token().size() > 4096u ||
        (request.has_user_action_id() &&
         request.user_action_id().size() > 4096u) ||
        !ValidTags(request) || token_hash.empty()) {
      SendFailure(std::move(event), "request_identity_invalid");
      return;
    }
    if (!BrowserAllowed(event->GetBrowserInfo())) {
      SendFailure(std::move(event), "untrusted_browser");
      return;
    }
    if (IsCancelled(item.action_hash)) {
      event->Close();
      Audit("request_cancelled",
            "\"request_token_sha256\":\"" + token_hash + "\"");
      return;
    }
    const time_t now = std::time(nullptr);
    if (!request.has_expires_at() || request.expires_at() <= now + 1) {
      SendFailure(std::move(event), "deadline_expired");
      return;
    }
    const std::string connector = ConnectorName(request);
    const std::string reason = ReasonName(request);
    if (connector == "UNKNOWN" || reason == "UNKNOWN") {
      SendFailure(std::move(event), "unsupported_request_shape");
      return;
    }
    std::vector<uint8_t> body;
    ScopedHandle held_file;
    std::string limitation;
    if (connector == "BULK_DATA_ENTRY" && request.has_text_content()) {
      if (request.text_content().size() > kMaxContentBytes) {
        limitation = "content_limit_exceeded";
      } else {
        body.assign(request.text_content().begin(), request.text_content().end());
      }
    } else if (connector == "FILE_ATTACHED" && request.has_file_path()) {
      SnapshotFile(request.file_path(), &body, &held_file, &limitation);
    } else {
      limitation = "unsupported_request_shape";
    }
    if (!limitation.empty()) {
      Wipe(&body);
      SendFailure(std::move(event), limitation);
      return;
    }
    if (!IsUtf8(body)) {
      Wipe(&body);
      SendFailure(std::move(event), "unsupported_content_encoding");
      return;
    }
    const std::string destination =
        request.has_request_data() && request.request_data().has_url()
            ? DestinationHost(request.request_data().url())
            : std::string();
    if (destination.empty()) {
      Wipe(&body);
      SendFailure(std::move(event), "destination_unknown");
      return;
    }
    const std::string body_sha256 = Sha256Hex(body);
    if (body_sha256.empty()) {
      Wipe(&body);
      SendFailure(std::move(event), "content_hash_failed");
      return;
    }
    std::string header = BuildPolicyHeader(
        request, destination, connector, reason, token_hash, item.action_hash,
        body_sha256, body.size());
    Config request_config = config_;
    const int64_t remaining_seconds = request.expires_at() - now - 1;
    const uint64_t deadline_budget_ms =
        static_cast<uint64_t>(remaining_seconds) * 1000u;
    request_config.timeout_ms = static_cast<DWORD>(
        std::min<uint64_t>(request_config.timeout_ms, deadline_budget_ms));
    const PolicyResult verdict =
        QueryPolicy(request_config, header, body, token_hash);
    if (!header.empty()) SecureZeroMemory(&header[0], header.size());
    Wipe(&body);
    if (IsCancelled(item.action_hash)) {
      event->Close();
      Audit("request_cancelled",
            "\"request_token_sha256\":\"" + token_hash + "\"");
      return;
    }
    if (request.expires_at() <= std::time(nullptr)) {
      SendFailure(std::move(event), "decision_deadline_expired");
      return;
    }
    if (verdict == PolicyResult::kAllow) {
      const ca::ResultCode result = event->Send();
      Audit("verdict_sent",
            "\"request_token_sha256\":\"" + token_hash +
                "\",\"verdict\":\"ALLOW\",\"send_result\":\"" +
                JsonEscape(ca::ResultCodeToString(result)) + "\"");
      return;
    }
    if (verdict == PolicyResult::kBlock) {
      if (ca::SetEventVerdictToBlock(event.get()) != ca::ResultCode::OK) {
        SendFailure(std::move(event), "block_response_failed");
        return;
      }
      const ca::ResultCode result = event->Send();
      Audit("verdict_sent",
            "\"request_token_sha256\":\"" + token_hash +
                "\",\"verdict\":\"BLOCK\",\"send_result\":\"" +
                JsonEscape(ca::ResultCodeToString(result)) + "\"");
      return;
    }
    SendFailure(std::move(event), "policy_unavailable_or_invalid");
  }

  void SendFailure(std::unique_ptr<ca::ContentAnalysisEvent> event,
                   const std::string& reason) {
    if (!event) return;
    const std::string token_hash = Sha256Hex(event->GetRequest().request_token());
    if (ca::UpdateResponse(event->GetResponse(), std::string(),
                           ca::ContentAnalysisResponse::Result::FAILURE) !=
        ca::ResultCode::OK) {
      event->Close();
      Audit("verdict_failed_closed",
            "\"request_token_sha256\":\"" + token_hash +
                "\",\"reason\":\"failure_response_unavailable\"");
      return;
    }
    const ca::ResultCode result = event->Send();
    Audit("verdict_sent",
          "\"request_token_sha256\":\"" + token_hash +
              "\",\"verdict\":\"FAILURE\",\"reason\":\"" +
              JsonEscape(reason) + "\",\"send_result\":\"" +
              JsonEscape(ca::ResultCodeToString(result)) + "\"");
  }

  Config config_;
  std::mutex browser_mutex_;
  std::map<DWORD, ProcessIdentity> browsers_;
  std::mutex queue_mutex_;
  std::condition_variable queue_ready_;
  std::deque<WorkItem> queue_;
  bool stopping_ = false;
  std::vector<std::thread> workers_;
  std::mutex cancel_mutex_;
  std::map<std::string, ULONGLONG> cancelled_actions_;
};

BOOL WINAPI ConsoleHandler(DWORD signal) {
  if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT ||
      signal == CTRL_CLOSE_EVENT || signal == CTRL_SHUTDOWN_EVENT) {
    ca::Agent* agent = g_agent.load();
    if (agent) agent->Stop();
    return TRUE;
  }
  return FALSE;
}

bool ParseUnsigned(const std::wstring& value, DWORD* result) {
  if (!result || value.empty()) return false;
  wchar_t* end = nullptr;
  errno = 0;
  const unsigned long parsed = std::wcstoul(value.c_str(), &end, 10);
  if (errno != 0 || !end || *end != L'\0' || parsed == 0 ||
      parsed > MAXDWORD) return false;
  *result = static_cast<DWORD>(parsed);
  return true;
}

bool ParseArguments(int argc, wchar_t** argv, Config* config) {
  if (!config) return false;
  for (int index = 1; index < argc; ++index) {
    const std::wstring argument(argv[index]);
    const std::wstring pipe_prefix = L"--policy-pipe=";
    const std::wstring pid_prefix = L"--policy-pid=";
    const std::wstring path_prefix = L"--browser-path=";
    const std::wstring chrome_prefix = L"--chrome-path=";
    const std::wstring timeout_prefix = L"--timeout-ms=";
    if (argument == L"--user") {
      continue;  // Only the user-specific path is implemented.
    } else if (argument == L"--policy-pipe" && index + 1 < argc) {
      config->policy_pipe = argv[++index];
    } else if (argument == L"--policy-pid" && index + 1 < argc) {
      if (!ParseUnsigned(argv[++index], &config->policy_pid)) return false;
    } else if ((argument == L"--chrome-path" ||
                argument == L"--browser-path") && index + 1 < argc) {
      config->allowed_browser_path = NormalizePath(argv[++index]);
    } else if (argument == L"--timeout-ms" && index + 1 < argc) {
      if (!ParseUnsigned(argv[++index], &config->timeout_ms) ||
          config->timeout_ms > 10000) return false;
    } else if (argument.compare(0, pipe_prefix.size(), pipe_prefix) == 0) {
      config->policy_pipe = argument.substr(pipe_prefix.size());
    } else if (argument.compare(0, pid_prefix.size(), pid_prefix) == 0) {
      if (!ParseUnsigned(argument.substr(pid_prefix.size()), &config->policy_pid))
        return false;
    } else if (argument.compare(0, path_prefix.size(), path_prefix) == 0) {
      config->allowed_browser_path =
          NormalizePath(argument.substr(path_prefix.size()));
    } else if (argument.compare(0, chrome_prefix.size(), chrome_prefix) == 0) {
      config->allowed_browser_path = NormalizePath(
          argument.substr(chrome_prefix.size()));
    } else if (argument.compare(0, timeout_prefix.size(), timeout_prefix) == 0) {
      if (!ParseUnsigned(argument.substr(timeout_prefix.size()), &config->timeout_ms) ||
          config->timeout_ms > 10000) return false;
    } else if (argument == L"--allow-sdk-test-client") {
      config->sdk_test_client = true;
    } else {
      return false;
    }
  }
  const std::wstring pipe_prefix = L"\\\\.\\pipe\\ttrace-content-policy-";
  return config->policy_pid != 0 && !config->allowed_browser_path.empty() &&
         config->policy_pipe.compare(0, pipe_prefix.size(), pipe_prefix) == 0 &&
         config->policy_pipe.size() <= 240;
}

void PrintUsage() {
  std::cerr
      << "Usage: ttrace-content-agent --policy-pipe=\\\\.\\pipe\\ttrace-content-policy-<nonce> "
      << "--policy-pid=<pid> --browser-path=<absolute-path> "
      << "[--user] [--timeout-ms=2000] [--allow-sdk-test-client]" << std::endl;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  Config config{};
  if (!ParseArguments(argc, argv, &config)) {
    PrintUsage();
    return 2;
  }
  if (!QueryProcessIdentity(config.policy_pid, &config.policy_identity)) {
    Audit("startup_failed", "\"reason\":\"policy_identity_unavailable\"");
    return 3;
  }
  config.allowed_browser_sha256 = Sha256File(config.allowed_browser_path);
  if (config.allowed_browser_sha256.empty()) {
    Audit("startup_failed", "\"reason\":\"browser_hash_unavailable\"");
    return 3;
  }
  if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) return 3;
  ca::ResultCode result = ca::ResultCode::OK;
  auto agent = ca::Agent::Create(
      {kSdkChannel, true}, std::unique_ptr<ca::AgentEventHandler>(
                               new Handler(std::move(config))),
      &result);
  if (!agent || result != ca::ResultCode::OK) {
    Audit("startup_failed",
          "\"result_code\":\"" + JsonEscape(ca::ResultCodeToString(result)) + "\"");
    return 4;
  }
  g_agent.store(agent.get());
  Audit("ready",
        "\"sdk_path\":\"path_user\",\"sdk_channel\":\"path_user\","
        "\"user_specific\":true");
  result = agent->HandleEvents();
  g_agent.store(nullptr);
  Audit("terminal",
        "\"result_code\":\"" + JsonEscape(ca::ResultCodeToString(result)) + "\"");
  return result == ca::ResultCode::OK ? 0 : 5;
}
