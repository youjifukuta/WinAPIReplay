#include "replay/config.h"
#include "replay/log_parser.h"
#include "replay/arg_preparer.h"
#include "replay/api_executor.h"
#include "replay/generic_dispatcher.h"
#include "replay/thread_manager.h"
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/pid_map.h"
#include "replay/path_sandbox.h"
#include "replay/registry_sandbox.h"
#include "replay/net_simulator.h"
#include "replay/result_writer.h"
#include "replay/utils.h"
#include "replay/executors/file_executor.h"
#include "replay/executors/registry_executor.h"
#include "replay/executors/network_executor.h"
#include "replay/executors/process_executor.h"
#include "replay/executors/dll_executor.h"
#include "replay/executors/sync_executor.h"
#include "replay/executors/crypto_executor.h"
#include "replay/executors/service_executor.h"
#include "replay/executors/shell_executor.h"
#include "replay/executors/hook_executor.h"
#include "replay/executors/token_executor.h"
#include "replay/executors/system_executor.h"
#include "replay/executors/nt_file_executor.h"
#include "replay/executors/nt_registry_executor.h"
#include "replay/executors/nt_memory_executor.h"
#include "replay/executors/nt_sync_executor.h"
#include "replay/executors/nt_misc_executor.h"
#include "replay/executors/ldr_executor.h"
#include <iostream>
#include <iomanip>

static void PrintSummary(const ReplayStats& stats) {
    std::cout << "[SUMMARY] total=" << stats.total
              << "  success=" << stats.success
              << "  failed="  << stats.failed
              << "  skipped=" << stats.skipped
              << "  approx="  << stats.approx << "\n";
}

int main(int argc, char* argv[]) {
    // stdout unbuffered: ensure output reaches file even on crash
    setvbuf(stdout, nullptr, _IONBF, 0);

    // 1. CLI 引数解析
    Config cfg = ParseArgs(argc, argv);

    // 2. ログ読み込み・シグネチャ DB ロード
    LogData log_data;
    try {
        log_data = LogParser{}.Parse(cfg.log_path);
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }

    SignatureDB sig_db;
    try {
        std::string sig_path = cfg.sig_path.empty() ? "data/api_signatures.json" : cfg.sig_path;
        sig_db.Load(sig_path);
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }

    // 3. 32bit ログ警告
    if (log_data.meta.process_bits == 32)
        std::cerr << "[WARN] 32-bit log: running as 64-bit best-effort\n";

    // 4. 安全機能の初期化
    PathSandbox     path_sandbox(cfg.sandbox_dir);
    RegistrySandbox reg_sandbox;
    if (cfg.sandbox_registry) reg_sandbox.Enable();

    NetSimulator net_sim;
    if (cfg.net_sim) net_sim.Start();

    // 5. 共有マップ
    HandleMap  handle_map;
    PointerMap pointer_map;
    PidMap     pid_map;

    // 6. Executor の初期化
    FileExecutor        file_ex  (handle_map, pointer_map, path_sandbox);
    NtFileExecutor      ntf_ex   (handle_map, pointer_map, path_sandbox);
    RegistryExecutor    reg_ex   (handle_map, pointer_map, reg_sandbox);
    NtRegistryExecutor  ntreg_ex (handle_map, pointer_map, reg_sandbox);
    NetworkExecutor     net_ex   (handle_map, pointer_map, net_sim);
    ProcessExecutor     proc_ex  (handle_map, pointer_map, pid_map, cfg.no_spawn);
    DllExecutor         dll_ex   (handle_map, pointer_map);
    LdrExecutor         ldr_ex   (handle_map, pointer_map);
    SyncExecutor        sync_ex  (handle_map, pointer_map, cfg.timeout_ms);
    NtSyncExecutor      ntsync_ex(handle_map, pointer_map, cfg.timeout_ms);
    NtMemoryExecutor    ntmem_ex (handle_map, pointer_map);
    CryptoExecutor      cryp_ex  (handle_map, pointer_map);
    ServiceExecutor     svc_ex   (handle_map, pointer_map);
    ShellExecutor       shll_ex  (handle_map, pointer_map, cfg.no_spawn);
    HookExecutor        hook_ex  (handle_map, pointer_map);
    TokenExecutor       tokn_ex  (handle_map, pointer_map);
    SystemExecutor      sys_ex   (handle_map, pointer_map);
    NtMiscExecutor      ntmisc_ex(handle_map, pointer_map, path_sandbox);
    GenericDispatcher gen_disp(handle_map);

    ArgPreparer arg_prep(sig_db, handle_map, pointer_map, pid_map,
                         path_sandbox, reg_sandbox);

    ApiExecutor api_exec(sig_db, arg_prep, handle_map, pointer_map, pid_map, cfg,
                         path_sandbox, reg_sandbox);
    ExecutorBase* executors[] = {
        &file_ex, &ntf_ex, &reg_ex, &ntreg_ex, &net_ex, &proc_ex,
        &dll_ex, &ldr_ex, &sync_ex, &ntsync_ex, &ntmem_ex, &cryp_ex, &svc_ex,
        &shll_ex, &hook_ex, &tokn_ex, &sys_ex, &ntmisc_ex
    };
    for (auto* ex : executors) api_exec.Register(ex);
    api_exec.SetGenericDispatcher(&gen_disp);

    // 7a. イベントループ前の初期化（ntdll関数ポインタ取得・サンドボックス事前構築）
    api_exec.PreInit(log_data.events);

    // 7b. スレッドグループ化と実行
    ThreadManager thread_mgr(api_exec, cfg.single_thread, cfg.timeout_ms);
    thread_mgr.GroupByThread(log_data.events);
    thread_mgr.Run();
    thread_mgr.WaitAll();

    // 8. 後処理
    if (cfg.net_sim)           net_sim.Stop();

    // 9. 結果出力（Cleanup の前に書き込む：Cleanup がクラッシュしても結果を保存するため）
    const ReplayStats& stats = api_exec.GetStats();
    if (!cfg.result_json.empty()) ResultWriter{}.Write(cfg, log_data, stats);
    PrintSummary(stats);

    // 10. サンドボックスクリーンアップ（結果書き込み後）
    if (cfg.sandbox_registry)  reg_sandbox.Cleanup();

    return (stats.failed > 0) ? 1 : 0;
}

// ── ParseArgs ──────────────────────────────────────────────────

static void PrintUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " <log.json>\n"
              << "  [--signatures <path>]  Signature DB (default: data/api_signatures.json)\n"
              << "  [--single-thread]      Run all events in seq order on one thread\n"
              << "  [--dry-run]            Skip all API calls\n"
              << "  [--timeout <ms>]       Per-API timeout (default: 5000)\n"
              << "  [--verbose]            Verbose output\n"
              << "  [--sandbox <dir>]      Redirect file paths into <dir>\n"
              << "  [--sandbox-registry]   Redirect registry to HKCU\\Software\\WinAPIReplaySandbox\n"
              << "  [--net-sim]            Replace network with loopback echo server\n"
              << "  [--no-spawn]           Skip CreateProcessW / ShellExecute\n"
              << "  [--no-l1-executor]     Force all APIs to Layer2 (ablation baseline)\n"
              << "  [--result-json <path>] Write replay results to JSON file\n";
}

Config ParseArgs(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        exit(1);
    }
    Config cfg;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--single-thread")    { cfg.single_thread    = true; }
        else if (arg == "--dry-run")     { cfg.dry_run          = true; }
        else if (arg == "--verbose")     { cfg.verbose          = true; }
        else if (arg == "--sandbox-registry") { cfg.sandbox_registry = true; }
        else if (arg == "--net-sim")     { cfg.net_sim          = true; }
        else if (arg == "--no-spawn")      { cfg.no_spawn         = true; }
        else if (arg == "--no-l1-executor"){ cfg.no_l1_executor   = true; }
        else if (arg == "--signatures") {
            if (++i >= argc) { PrintUsage(argv[0]); exit(1); }
            cfg.sig_path = argv[i];
        }
        else if (arg == "--timeout") {
            if (++i >= argc) { PrintUsage(argv[0]); exit(1); }
            try { cfg.timeout_ms = (DWORD)std::stoul(argv[i]); }
            catch (...) { PrintUsage(argv[0]); exit(1); }
            if (cfg.timeout_ms == 0) { PrintUsage(argv[0]); exit(1); }
        }
        else if (arg == "--sandbox") {
            if (++i >= argc) { PrintUsage(argv[0]); exit(1); }
            cfg.sandbox_dir = Utf8ToWide(argv[i]);
        }
        else if (arg == "--result-json") {
            if (++i >= argc) { PrintUsage(argv[0]); exit(1); }
            cfg.result_json = argv[i];
        }
        else if (arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n";
            PrintUsage(argv[0]);
            exit(1);
        }
        else {
            cfg.log_path = arg;
        }
    }
    if (cfg.log_path.empty()) {
        PrintUsage(argv[0]);
        exit(1);
    }
    return cfg;
}
