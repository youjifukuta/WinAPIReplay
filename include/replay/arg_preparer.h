#pragma once
#include "log_types.h"
#include "handle_map.h"
#include "pointer_map.h"
#include "pid_map.h"
#include "path_sandbox.h"
#include "registry_sandbox.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>

// ── シグネチャ型定義 ──────────────────────────────────────────────

struct ArgSpec {
    std::string type;
    int         size_bytes   = 0;
    int         size_arg     = -1;
    int         default_size = 65536;
};

struct OutHandleSpec {
    std::string handle_type;  // "HKEY" / "HANDLE" / "HCRYPTPROV" / "HCRYPTHASH" / "PROCESS_INFORMATION"
    int         arg_idx;
    std::string key;          // PROCESS_INFORMATION 以外で使用
};

struct ApiSignature {
    std::string                   module;
    std::string                   category;
    std::vector<ArgSpec>          args;
    std::string                   return_type;
    std::optional<OutHandleSpec>  out_handle;
    std::optional<int>            invalidates_arg;
};

// ── SignatureDB ───────────────────────────────────────────────────

class SignatureDB {
public:
    void                  Load(const std::string& path);
    const ApiSignature*   Find(const std::string& api_name) const;
    bool                  IsLayer1(const std::string& api_name) const;

private:
    std::unordered_map<std::string, ApiSignature> db_;
};

// ── PreparedArgs ─────────────────────────────────────────────────

struct PreparedArg {
    DWORD_PTR           value      = 0;
    std::vector<BYTE>   buffer;
    std::vector<HANDLE> handle_arr;
};

struct SizeInoutInfo {
    int size_inout_idx = -1;
    int data_out_idx   = -1;
};

// Records a single sandbox argument transformation applied by ArgPreparer::Prepare().
// Enables post-processing tools (e.g. Sysmon log correctors) to map sandboxed
// paths and registry keys back to the original malware-intended values.
struct SandboxTransform {
    int         param_index;   // 0-based index of the rewritten argument
    std::string original;      // value from the original log (UTF-8)
    std::string rewritten;     // value actually passed to the Win32 call (UTF-8)
};

struct PreparedArgs {
    std::vector<PreparedArg>       args;
    std::vector<DWORD_PTR>         raw;
    std::optional<SizeInoutInfo>   size_inout;   // for ERROR_INSUFFICIENT_BUFFER retry
    std::vector<SandboxTransform>  transforms;   // sandbox path/registry redirections applied
};

// ── ArgPreparer ──────────────────────────────────────────────────

class ArgPreparer {
public:
    ArgPreparer(const SignatureDB& sig_db,
                HandleMap&         handle_map,
                PointerMap&        pointer_map,
                PidMap&            pid_map,
                PathSandbox&       path_sandbox,
                RegistrySandbox&   reg_sandbox)
        : sig_db_(sig_db)
        , handle_map_(handle_map)
        , pointer_map_(pointer_map)
        , pid_map_(pid_map)
        , path_sandbox_(path_sandbox)
        , reg_sandbox_(reg_sandbox) {}

    PreparedArgs Prepare(const LogEvent& event, const ApiSignature& sig) const;

private:
    const SignatureDB&  sig_db_;
    HandleMap&          handle_map_;
    PointerMap&         pointer_map_;
    PidMap&             pid_map_;
    PathSandbox&        path_sandbox_;
    RegistrySandbox&    reg_sandbox_;
};
