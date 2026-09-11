#pragma once
#include "log_types.h"
#include "arg_preparer.h"
#include "handle_map.h"
#include "pointer_map.h"
#include "pid_map.h"
#include "path_sandbox.h"
#include "registry_sandbox.h"
#include "config.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

// ── ExecutorBase ─────────────────────────────────────────────────

class ApiExecutor;  // forward declaration

class ExecutorBase {
public:
    explicit ExecutorBase(HandleMap& hmap, PointerMap& pmap)
        : handle_map_(hmap), pointer_map_(pmap) {}
    virtual ~ExecutorBase() = default;

    virtual std::vector<std::string> SupportedApis() const = 0;
    virtual DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) = 0;

    // Called once before the event loop starts (after ntdll function pointers are loaded).
    virtual void Initialize() {}

protected:
    HandleMap&  handle_map_;
    PointerMap& pointer_map_;
};

// ── ReplayStats ──────────────────────────────────────────────────

struct EventResult {
    int         seq           = 0;
    std::string api_name;
    std::string outcome;        // "success" / "failed" / "skipped" / "approx"
    std::string actual_return;  // "0x..." or empty (skipped)
    std::string note;           // reason / annotation
    std::vector<SandboxTransform> transforms;  // sandbox path/registry redirections
};

// Process creation telemetry reconstructed from CreateProcessW/A arguments.
// Recorded regardless of whether the spawn was actually executed (--no-spawn
// skips the OS call but we still want the telemetry).
struct ProcessEvent {
    int         seq               = 0;
    std::string api_name;           // "CreateProcessW" | "CreateProcessA"
    std::string application;        // lpApplicationName (may be empty)
    std::string command_line;       // lpCommandLine
    std::string current_directory;  // lpCurrentDirectory (may be empty)
    std::string outcome;            // mirrors the EventResult outcome
};

struct ReplayStats {
    int total   = 0;
    int success = 0;
    int failed  = 0;
    int skipped = 0;
    int approx  = 0;

    std::vector<EventResult>  results;
    std::vector<ProcessEvent> process_events;  // Extension B: process creation telemetry

    void Record(const EventResult& r);

private:
    mutable std::mutex mutex_;
};

// ── GenericDispatcher forward ─────────────────────────────────────

class GenericDispatcher;

// ── ApiExecutor ───────────────────────────────────────────────────

class ApiExecutor {
public:
    ApiExecutor(const SignatureDB& sig_db,
                ArgPreparer&       arg_prep,
                HandleMap&         handle_map,
                PointerMap&        pointer_map,
                PidMap&            pid_map,
                const Config&      cfg,
                PathSandbox&       path_sandbox,
                RegistrySandbox&   reg_sandbox);

    void Register(ExecutorBase* executor);
    void SetGenericDispatcher(GenericDispatcher* gd) { generic_dispatcher_ = gd; }

    // Must be called once before the event loop.
    // Loads ntdll function pointers, pre-creates sandbox file directories,
    // pre-creates sandbox registry keys, and initialises each registered executor.
    void PreInit(const std::vector<LogEvent>& events);

    void Execute(const LogEvent& event);

    const ReplayStats& GetStats() const { return stats_; }

    // Called by executors / internally
    void LogResult(const LogEvent& event, DWORD_PTR result,
                   const std::string& outcome, const std::string& note = "",
                   std::vector<SandboxTransform> transforms = {});
    void LogSkip(const LogEvent& event, const std::string& reason);
    void LogApprox(const LogEvent& event, DWORD_PTR result, const std::string& note,
                   std::vector<SandboxTransform> transforms = {});

private:
    std::string DetermineOutcome(const std::string& return_type, DWORD_PTR result) const;
    void UpdateMaps(const LogEvent& event, const ApiSignature& sig,
                    const PreparedArgs& prepared, DWORD_PTR result);

    std::string FormatArgList(const LogEvent& event,
                              const ApiSignature& sig,
                              const PreparedArgs& prepared) const;

    // Try to synthesize a handle for handle-creating NT/Win32 APIs.
    // Registers the synthesized handle in handle_map_ so subsequent Layer1
    // calls (ReadFile, RegQueryValueExW, etc.) can find it.
    // Returns true if a handle was successfully synthesized and registered.
    bool TrySynthHandle(const LogEvent& event);

    // Build a reverse map: original_handle_value → index in all_events_.
    // Called once in PreInit after the event list is available.
    void BuildHandleOriginIndex(const std::vector<LogEvent>& events);

    // Attempt to resolve an unmapped handle by finding its creation event
    // via handle_origin_idx_ and calling TrySynthHandle on it.
    bool TrySynthHandleByValue(DWORD_PTR original);

    const SignatureDB&    sig_db_;
    ArgPreparer&          arg_prep_;
    HandleMap&            handle_map_;
    PointerMap&           pointer_map_;
    PidMap&               pid_map_;
    const Config&         cfg_;
    PathSandbox&          path_sandbox_;
    RegistrySandbox&      reg_sandbox_;

    std::unordered_map<std::string, ExecutorBase*> dispatch_table_;
    GenericDispatcher*                              generic_dispatcher_ = nullptr;

    // handle_dep resolver: maps original-handle-value → event index in all_events_.
    std::unordered_map<DWORD_PTR, size_t>  handle_origin_idx_;
    const std::vector<LogEvent>*            all_events_ = nullptr;

    ReplayStats        stats_;
    mutable std::mutex output_mutex_;
};
