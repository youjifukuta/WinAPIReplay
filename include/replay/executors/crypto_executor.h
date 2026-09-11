#pragma once
#include "replay/api_executor.h"
#include <wincrypt.h>
#include <unordered_map>

class CryptoExecutor : public ExecutorBase {
public:
    using ExecutorBase::ExecutorBase;
    ~CryptoExecutor();

    std::vector<std::string> SupportedApis() const override;
    DWORD_PTR Execute(const LogEvent& event, const PreparedArgs& prepared) override;

private:
    // Lazy synthesis: maps original (malware) handle values → synthesized handles.
    // Needed because WinMET does not record phProv / phHash output values, so
    // UpdateMaps() cannot register them; we detect unmapped handles at call time
    // and synthesize on the spot.
    std::unordered_map<DWORD_PTR, HCRYPTPROV> synth_provs_;
    std::unordered_map<DWORD_PTR, HCRYPTHASH> synth_hashes_;

    // Holds the most recently created-but-not-yet-registered HCRYPTHASH.
    // Set by CryptCreateHash when we synthesize the provider; consumed by the
    // next CryptHashData / CryptDestroyHash call that needs the same hash.
    HCRYPTHASH pending_hash_ = 0;

    // Extract the original handle value from event.args[arg_idx].
    static DWORD_PTR OrigHandle(const LogEvent& event, int arg_idx);

    // Return or synthesize an HCRYPTPROV for the original handle value in
    // event.args[0]. Always returns a valid provider or 0 on hard failure.
    HCRYPTPROV GetOrSynthProv(const LogEvent& event);

    // Return or synthesize an HCRYPTHASH for the original handle value in
    // event.args[0]. Uses pending_hash_ first, then creates a new MD5 hash.
    HCRYPTHASH GetOrSynthHash(const LogEvent& event);
};
