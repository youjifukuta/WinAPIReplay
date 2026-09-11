#include "replay/executors/crypto_executor.h"
#include "replay/utils.h"
#include <wincrypt.h>

// ── Destructor: release all synthesized handles ────────────────────────────────

CryptoExecutor::~CryptoExecutor() {
    for (auto& [orig, h] : synth_hashes_) CryptDestroyHash(h);
    for (auto& [orig, p] : synth_provs_) CryptReleaseContext(p, 0);
    if (pending_hash_) CryptDestroyHash(pending_hash_);
}

// ── Static helper ─────────────────────────────────────────────────────────────

DWORD_PTR CryptoExecutor::OrigHandle(const LogEvent& event, int idx) {
    if (idx >= (int)event.args.size()) return 0;
    if (auto* ws = std::get_if<std::wstring>(&event.args[idx])) {
        try { return HexToPtr(WideToUtf8(*ws)); } catch (...) {}
    } else if (auto* iv = std::get_if<std::int64_t>(&event.args[idx])) {
        return (DWORD_PTR)*iv;
    }
    return 0;
}

// ── Provider synthesis ────────────────────────────────────────────────────────

HCRYPTPROV CryptoExecutor::GetOrSynthProv(const LogEvent& event) {
    DWORD_PTR orig = OrigHandle(event, 0);
    if (orig != 0) {
        auto it = synth_provs_.find(orig);
        if (it != synth_provs_.end()) return it->second;
    }
    HCRYPTPROV prov = 0;
    if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
        !CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return 0;
    if (orig != 0) {
        synth_provs_[orig] = prov;
        handle_map_.Register(orig, (DWORD_PTR)prov);
    }
    return prov;
}

// ── Hash synthesis ────────────────────────────────────────────────────────────

HCRYPTHASH CryptoExecutor::GetOrSynthHash(const LogEvent& event) {
    DWORD_PTR orig = OrigHandle(event, 0);

    // 1. Already mapped in handle_map (registered by UpdateMaps on a previous call)
    if (orig != 0 && handle_map_.HasMapping(orig))
        return (HCRYPTHASH)handle_map_.Resolve(orig);

    // 2. In our local hash cache
    if (orig != 0) {
        auto it = synth_hashes_.find(orig);
        if (it != synth_hashes_.end()) return it->second;
    }

    // 3. Consume the pending hash left by the preceding CryptCreateHash
    if (pending_hash_ != 0) {
        HCRYPTHASH h = pending_hash_;
        pending_hash_ = 0;
        if (orig != 0) {
            synth_hashes_[orig] = h;
            handle_map_.Register(orig, (DWORD_PTR)h);
        }
        return h;
    }

    // 4. Last resort: synthesize a fresh MD5 hash from a temporary provider
    HCRYPTPROV tmp_prov = 0;
    if (!CryptAcquireContextW(&tmp_prov, nullptr, nullptr,
                              PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return 0;
    HCRYPTHASH h = 0;
    CryptCreateHash(tmp_prov, CALG_MD5, 0, 0, &h);
    CryptReleaseContext(tmp_prov, 0);
    if (h != 0 && orig != 0) {
        synth_hashes_[orig] = h;
        handle_map_.Register(orig, (DWORD_PTR)h);
    }
    return h;
}

// ── SupportedApis ─────────────────────────────────────────────────────────────

std::vector<std::string> CryptoExecutor::SupportedApis() const {
    return {
        "CryptAcquireContextW", "CryptAcquireContextA",
        "CryptCreateHash",
        "CryptHashData",
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptDestroyHash",
        "CryptReleaseContext",
    };
}

// ── Execute ───────────────────────────────────────────────────────────────────

DWORD_PTR CryptoExecutor::Execute(const LogEvent& event, const PreparedArgs& p) {
    const auto& n = event.api_name;

    // CryptAcquireContextW/A
    // WinMET data gap: WinMET records (szContainer, szProvider, <value>) but omits
    // dwProvType.  The 3rd WinMET arg (which may be CRYPT_VERIFYCONTEXT=0xF0000000)
    // lands in p.raw[3] (the dwProvType slot) while p.raw[4] (dwFlags) is 0.
    // Fix: if p.raw[3] > 100 (no valid provider type) and p.raw[4]==0, treat
    // p.raw[3] as dwFlags and use PROV_RSA_AES as the provider type.
    // On any failure, fall back to a null-provider synthesis call.
    if (n == "CryptAcquireContextW") {
        DWORD dwProvType = (DWORD)p.raw[3];
        DWORD dwFlags    = (DWORD)p.raw[4];
        if (dwFlags == 0 && dwProvType > 100) { dwFlags = dwProvType; dwProvType = PROV_RSA_AES; }
        BOOL r = CryptAcquireContextW(
            (HCRYPTPROV*)p.raw[0], (LPCWSTR)p.raw[1], (LPCWSTR)p.raw[2],
            dwProvType, dwFlags);
        if (!r && GetLastError() == NTE_BAD_KEYSET)
            r = CryptAcquireContextW(
                (HCRYPTPROV*)p.raw[0], (LPCWSTR)p.raw[1], (LPCWSTR)p.raw[2],
                dwProvType, dwFlags | CRYPT_NEWKEYSET);
        // Final fallback: synthesize with safe defaults (empty-container verifycontext)
        if (!r)
            r = CryptAcquireContextW(
                (HCRYPTPROV*)p.raw[0], nullptr, nullptr,
                PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
        return (DWORD_PTR)r;
    }
    if (n == "CryptAcquireContextA") {
        DWORD dwProvType = (DWORD)p.raw[3];
        DWORD dwFlags    = (DWORD)p.raw[4];
        if (dwFlags == 0 && dwProvType > 100) { dwFlags = dwProvType; dwProvType = PROV_RSA_AES; }
        BOOL r = CryptAcquireContextA(
            (HCRYPTPROV*)p.raw[0], (LPCSTR)p.raw[1], (LPCSTR)p.raw[2],
            dwProvType, dwFlags);
        if (!r && GetLastError() == NTE_BAD_KEYSET)
            r = CryptAcquireContextA(
                (HCRYPTPROV*)p.raw[0], (LPCSTR)p.raw[1], (LPCSTR)p.raw[2],
                dwProvType, dwFlags | CRYPT_NEWKEYSET);
        if (!r)
            r = CryptAcquireContextW(
                (HCRYPTPROV*)p.raw[0], nullptr, nullptr,
                PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
        return (DWORD_PTR)r;
    }

    // CryptCreateHash
    // WinMET data gap: WinMET records [ALG_ID, hKey, phHash_output] for CryptCreateHash,
    // not [hProv, ALG_ID, hKey, dwFlags, phHash_out] as in the API signature.
    // The signature maps WinMET-args[0] (ALG_ID) into p.raw[0] (the hProv HANDLE slot),
    // and WinMET-args[1] (hKey=0) into p.raw[1] (the ALG_ID slot) → ALG_ID becomes 0.
    // Detection: if p.raw[1]==0 and p.raw[0] looks like an ALG_ID (0x8000–0x9FFF),
    // swap: real ALG_ID = p.raw[0], hProv = synth, real orig_phHash = from event.args[2].
    if (n == "CryptCreateHash") {
        HCRYPTPROV hProv = (HCRYPTPROV)p.raw[0];
        ALG_ID     algId = (ALG_ID)p.raw[1];

        // WinMET format shift detection
        if (algId == 0 && hProv != 0 && (hProv & 0xFFFF8000) == 0x00008000) {
            algId = (ALG_ID)hProv;
            hProv = 0;  // will be synthesized below
        }
        if (algId == 0) algId = CALG_MD5;  // last-resort default

        if (hProv == 0) hProv = GetOrSynthProv(event);
        if (hProv == 0) return FALSE;

        HCRYPTHASH synth_hash = 0;
        BOOL r = CryptCreateHash(hProv, algId, 0, 0, &synth_hash);
        if (r && synth_hash != 0) {
            pending_hash_ = synth_hash;
            // Register against the original phHash value recorded in WinMET args[2]
            // (which the signature misidentifies as hKey slot → p.raw[2] after resolve)
            DWORD_PTR orig_hash = OrigHandle(event, 2);
            if (orig_hash == 0) orig_hash = OrigHandle(event, 4);  // fallback
            if (orig_hash != 0) {
                synth_hashes_[orig_hash] = synth_hash;
                handle_map_.Register(orig_hash, (DWORD_PTR)synth_hash);
            }
            if (p.raw[4] != 0)
                *reinterpret_cast<HCRYPTHASH*>(p.raw[4]) = synth_hash;
        }
        return (DWORD_PTR)r;
    }

    // CryptHashData
    // WinMET records [hHash, pbData, dwDataLen] matching the signature.
    // p.raw[0] = resolved hHash (0 if unmapped → synthesize)
    if (n == "CryptHashData") {
        HCRYPTHASH hHash = (HCRYPTHASH)p.raw[0];
        if (hHash == 0) hHash = GetOrSynthHash(event);
        if (hHash == 0) return FALSE;
        // Hash dummy data (same size as original; content irrelevant for success/fail)
        DWORD len = (DWORD)p.raw[2];
        std::vector<BYTE> dummy(len > 0 ? len : 1, 0xAA);
        return (DWORD_PTR)CryptHashData(hHash, dummy.data(), len, (DWORD)p.raw[3]);
    }

    // CryptEncrypt / CryptDecrypt: if hKey or hHash unmapped, return TRUE
    // (pretend success; we cannot easily synthesize a key handle here)
    if (n == "CryptEncrypt") {
        if (p.raw[0] == 0) return TRUE; // unmapped hKey → fake success
        return (DWORD_PTR)CryptEncrypt(
            (HCRYPTKEY)p.raw[0], (HCRYPTHASH)p.raw[1],
            (BOOL)p.raw[2], (DWORD)p.raw[3],
            (BYTE*)p.raw[4], (LPDWORD)p.raw[5], (DWORD)p.raw[6]);
    }
    if (n == "CryptDecrypt") {
        if (p.raw[0] == 0) return TRUE; // unmapped hKey → fake success
        return (DWORD_PTR)CryptDecrypt(
            (HCRYPTKEY)p.raw[0], (HCRYPTHASH)p.raw[1],
            (BOOL)p.raw[2], (DWORD)p.raw[3],
            (BYTE*)p.raw[4], (LPDWORD)p.raw[5]);
    }

    // CryptDestroyHash
    if (n == "CryptDestroyHash") {
        HCRYPTHASH hHash = (HCRYPTHASH)p.raw[0];
        if (hHash == 0) {
            hHash = GetOrSynthHash(event);
            if (hHash == 0) return TRUE; // nothing to destroy
        }
        BOOL r = CryptDestroyHash(hHash);
        // Remove from local cache so we don't double-free
        DWORD_PTR orig = OrigHandle(event, 0);
        if (orig != 0) synth_hashes_.erase(orig);
        return (DWORD_PTR)r;
    }

    if (n == "CryptReleaseContext")
        return (DWORD_PTR)CryptReleaseContext((HCRYPTPROV)p.raw[0], (DWORD)p.raw[1]);

    return 0;
}
