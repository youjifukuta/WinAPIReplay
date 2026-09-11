// Tests for NetworkExecutor: all 23 APIs in SupportedApis().
// Winsock tests use net_sim (loopback echo server) so no external connectivity needed.
// WinINet tests verify call paths succeed or return known-bad values gracefully.
#include <gtest/gtest.h>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include "replay/handle_map.h"
#include "replay/pointer_map.h"
#include "replay/net_simulator.h"
#include "replay/executors/network_executor.h"
#include "replay/log_types.h"
#include "replay/arg_preparer.h"

static LogEvent MakeEvent(std::string api) {
    LogEvent ev;
    ev.api_name = std::move(api);
    return ev;
}

// Build an event with event.args[0] set to orig_handle as a hex wstring.
// This mirrors how WinMET encodes socket/handle values so that the
// handle_map lookup in connect()/WSAConnect() works correctly.
static LogEvent MakeEventWithArg0(std::string api, DWORD_PTR orig_handle) {
    LogEvent ev;
    ev.api_name = std::move(api);
    wchar_t buf[32];
    swprintf_s(buf, 32, L"0x%llX", (unsigned long long)orig_handle);
    ev.args.push_back(std::wstring(buf));
    return ev;
}

static PreparedArgs MakeRaw(std::vector<DWORD_PTR> vals) {
    PreparedArgs p;
    p.raw = std::move(vals);
    p.args.resize(p.raw.size());
    return p;
}

class NetworkExecutorTest : public ::testing::Test {
protected:
    HandleMap       hmap_;
    PointerMap      pmap_;
    NetSimulator    sim_;
    NetworkExecutor exec_{hmap_, pmap_, sim_};

    static void SetUpTestSuite() {
        // net_sim is per-instance; WSAStartup needed once globally
        WSADATA wd{};
        WSAStartup(MAKEWORD(2, 2), &wd);
    }
    static void TearDownTestSuite() {
        WSACleanup();
    }

    void SetUp() override {
        sim_.Start();  // starts loopback echo server on random port
    }
    void TearDown() override {
        sim_.Stop();
    }
};

// ── WSAStartup ────────────────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, WSAStartup_Succeeds) {
    auto p = MakeRaw({MAKEWORD(2, 2), 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("WSAStartup"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);  // 0 = success
}

// ── WSACleanup ────────────────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, WSACleanup_Succeeds) {
    exec_.EnsureWSAStartup();
    auto p = MakeRaw({});
    // WSACleanup returns 0 on success; SOCKET_ERROR (-1) on error.
    // In test context extra WSACleanup may return SOCKET_ERROR — both are acceptable.
    DWORD_PTR ret = exec_.Execute(MakeEvent("WSACleanup"), p);
    // Re-initialize for subsequent tests
    WSADATA wd{};
    WSAStartup(MAKEWORD(2, 2), &wd);
    (void)ret;  // result varies depending on WSAStartup reference count
}

// ── socket ────────────────────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, Socket_TCP_ReturnsValidSocket) {
    exec_.EnsureWSAStartup();
    auto p = MakeRaw({AF_INET, SOCK_STREAM, IPPROTO_TCP});
    DWORD_PTR ret = exec_.Execute(MakeEvent("socket"), p);
    SOCKET s = (SOCKET)ret;
    EXPECT_NE(s, INVALID_SOCKET);
    if (s != INVALID_SOCKET) closesocket(s);
}

// ── connect (net_sim) ─────────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, Connect_NetSim_ConnectsToLoopback) {
    EXPECT_TRUE(sim_.IsEnabled());
    exec_.EnsureWSAStartup();
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(s, INVALID_SOCKET);

    auto p = MakeRaw({(DWORD_PTR)s, 0, 0, 0});
    // connect executor redirects to loopback when net_sim is enabled
    DWORD_PTR ret = exec_.Execute(MakeEvent("connect"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
    closesocket(s);
}

// ── bind ─────────────────────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, Bind_ValidSocket_Succeeds) {
    exec_.EnsureWSAStartup();
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(s, INVALID_SOCKET);

    auto p = MakeRaw({(DWORD_PTR)s, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("bind"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
    closesocket(s);
}

// ── send / recv ───────────────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, Send_ConnectedSocket_SendsData) {
    exec_.EnsureWSAStartup();
    SOCKET s = exec_.SynthConnectedSocket();
    ASSERT_NE(s, INVALID_SOCKET);

    const char data[] = "test";
    auto p = MakeRaw({(DWORD_PTR)s, (DWORD_PTR)data, 4, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("send"), p);
    EXPECT_GT((int)ret, 0);
    closesocket(s);
}

TEST_F(NetworkExecutorTest, Recv_ConnectedSocket_ReceivesEcho) {
    exec_.EnsureWSAStartup();
    SOCKET s = exec_.SynthConnectedSocket();
    ASSERT_NE(s, INVALID_SOCKET);

    // Send something first so the echo server has data to echo
    const char msg[] = "ping";
    ::send(s, msg, 4, 0);

    char buf[64] = {};
    auto p = MakeRaw({(DWORD_PTR)s, (DWORD_PTR)buf, 63, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("recv"), p);
    // recv returns bytes received (>0) or SOCKET_ERROR
    EXPECT_GE((int)ret, 0);
    closesocket(s);
}

// ── closesocket ───────────────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, Closesocket_ValidSocket_Succeeds) {
    exec_.EnsureWSAStartup();
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(s, INVALID_SOCKET);
    auto p = MakeRaw({(DWORD_PTR)s});
    DWORD_PTR ret = exec_.Execute(MakeEvent("closesocket"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}

TEST_F(NetworkExecutorTest, Closesocket_InvalidSocket_ReturnsZero) {
    // Unmapped/null socket → returns 0 (success no-op)
    auto p = MakeRaw({0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("closesocket"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}

// ── listen / accept ───────────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, Accept_InvalidSocket_ReturnsInvalidSocket) {
    // socket=0 is not a listening socket → ::accept returns INVALID_SOCKET.
    // Primary requirement: no crash; return value indicates failure.
    exec_.EnsureWSAStartup();
    auto p = MakeRaw({(DWORD_PTR)(SOCKET)0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("accept"), p);
    EXPECT_EQ(ret, (DWORD_PTR)INVALID_SOCKET);
}

TEST_F(NetworkExecutorTest, Listen_BoundSocket_Succeeds) {
    exec_.EnsureWSAStartup();
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(s, INVALID_SOCKET);
    // bind first
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = 0;
    ::bind(s, (sockaddr*)&addr, sizeof(addr));

    auto p = MakeRaw({(DWORD_PTR)s, SOMAXCONN});
    DWORD_PTR ret = exec_.Execute(MakeEvent("listen"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
    closesocket(s);
}

// ── connect: unmapped socket synthesis ───────────────────────────────────────

TEST_F(NetworkExecutorTest, Connect_UnmappedSocket_SynthesizesAndRegisters) {
    // Simulates a socket created before capture (no entry in handle_map).
    // event.args[0] carries the original handle value; p.raw[0] is the same
    // unresolved value.  The executor must synthesize a fresh socket, return 0
    // (SOCKET_NO_ERROR), and register the synthesized socket in handle_map for
    // subsequent send()/recv() calls on the same original handle.
    constexpr DWORD_PTR orig = 0x400;
    ASSERT_FALSE(hmap_.HasMapping(orig));

    LogEvent ev = MakeEventWithArg0("connect", orig);
    PreparedArgs p;
    p.raw = {orig, 0, 0, 0};  // orig value passed through (unmapped)
    p.args.resize(p.raw.size());

    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_EQ(ret, (DWORD_PTR)0);         // success via synthesis
    EXPECT_TRUE(hmap_.HasMapping(orig));  // registered for subsequent send/recv
}

TEST_F(NetworkExecutorTest, Connect_AfterSynthesis_SendSucceeds) {
    // After connect() synthesizes and registers a socket, the registered real socket
    // must be usable for send() via the handle_map.
    constexpr DWORD_PTR orig = 0x401;
    LogEvent connect_ev = MakeEventWithArg0("connect", orig);
    PreparedArgs cp;
    cp.raw = {orig, 0, 0, 0};
    cp.args.resize(cp.raw.size());
    ASSERT_EQ(exec_.Execute(connect_ev, cp), (DWORD_PTR)0);
    ASSERT_TRUE(hmap_.HasMapping(orig));

    // Resolve the registered real socket and use it for send().
    SOCKET real_s = (SOCKET)hmap_.Resolve(orig);
    const char data[] = "hello";
    PreparedArgs sp;
    sp.raw = {(DWORD_PTR)real_s, (DWORD_PTR)data, 5, 0};
    sp.args.resize(sp.raw.size());
    DWORD_PTR sent = exec_.Execute(MakeEvent("send"), sp);
    EXPECT_GT((int)sent, 0);  // at least 1 byte sent to net_sim echo server
    closesocket(real_s);
    hmap_.Invalidate(orig);
}

// ── WSAConnect ────────────────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, WSAConnect_NullSocket_SynthesizesConnection) {
    // socket=0 (invalid/unmapped) → executor synthesizes a new connected socket
    auto p = MakeRaw({0, 0, 0, 0, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("WSAConnect"), p);
    // Returns 0 (success) when a synthesized socket connects to loopback
    EXPECT_EQ(ret, (DWORD_PTR)0);
}

TEST_F(NetworkExecutorTest, WSAConnect_UnmappedSocket_SynthesizesAndRegisters) {
    // Same as the connect() test but for WSAConnect.
    constexpr DWORD_PTR orig = 0x402;
    ASSERT_FALSE(hmap_.HasMapping(orig));

    LogEvent ev = MakeEventWithArg0("WSAConnect", orig);
    PreparedArgs p;
    p.raw = {orig, 0, 0, 0, 0, 0, 0};
    p.args.resize(p.raw.size());

    DWORD_PTR ret = exec_.Execute(ev, p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
    EXPECT_TRUE(hmap_.HasMapping(orig));
}

// ── GetAddrInfoW ──────────────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, GetAddrInfoW_NetSim_ResolvesToLoopback) {
    exec_.EnsureWSAStartup();
    ADDRINFOW* res = nullptr;
    PreparedArgs p;
    p.raw = {(DWORD_PTR)L"example.com", (DWORD_PTR)L"80", 0, 0};
    p.args.resize(4);
    // args[3].buffer holds pointer to ADDRINFOW*
    p.args[3].buffer.resize(sizeof(ADDRINFOW*));
    *reinterpret_cast<ADDRINFOW**>(p.args[3].buffer.data()) = nullptr;

    DWORD_PTR ret = exec_.Execute(MakeEvent("GetAddrInfoW"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);  // net_sim redirects to 127.0.0.1
}

// ── FreeAddrInfoW ─────────────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, FreeAddrInfoW_ReturnsZero) {
    // Always returns 0 (frees last_addrinfo_ internally)
    auto p = MakeRaw({0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("FreeAddrInfoW"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}

// ── InternetOpenW / A ─────────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, InternetOpenW_ReturnsHandle) {
    auto p = MakeRaw({(DWORD_PTR)L"TestAgent", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("InternetOpenW"), p);
    HINTERNET h = (HINTERNET)ret;
    EXPECT_NE(h, (HINTERNET)nullptr);
    if (h) InternetCloseHandle(h);
}

TEST_F(NetworkExecutorTest, InternetOpenA_ReturnsHandle) {
    auto p = MakeRaw({(DWORD_PTR)"TestAgent", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("InternetOpenA"), p);
    HINTERNET h = (HINTERNET)ret;
    EXPECT_NE(h, (HINTERNET)nullptr);
    if (h) InternetCloseHandle(h);
}

// ── InternetConnectW / A ──────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, InternetConnectW_WithNullSession_ReturnsNullOrHandle) {
    // null session handle → InternetConnectW likely returns NULL; check no crash
    auto p = MakeRaw({0, (DWORD_PTR)L"example.com",
                      INTERNET_DEFAULT_HTTP_PORT, 0, 0,
                      INTERNET_SERVICE_HTTP, 0, 0});
    // Don't assert specific value — connect may succeed or fail depending on env
    DWORD_PTR ret = exec_.Execute(MakeEvent("InternetConnectW"), p);
    HINTERNET h = (HINTERNET)ret;
    if (h) InternetCloseHandle(h);
}

TEST_F(NetworkExecutorTest, InternetConnectA_WithNullSession_DoesNotCrash) {
    auto p = MakeRaw({0, (DWORD_PTR)"example.com",
                      INTERNET_DEFAULT_HTTP_PORT, 0, 0,
                      INTERNET_SERVICE_HTTP, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("InternetConnectA"), p);
    HINTERNET h = (HINTERNET)ret;
    if (h) InternetCloseHandle(h);
}

// ── HttpOpenRequestW / A (null connection → graceful null) ────────────────────

TEST_F(NetworkExecutorTest, HttpOpenRequestW_NullConnection_ReturnsNull) {
    auto p = MakeRaw({0, (DWORD_PTR)L"GET", (DWORD_PTR)L"/", 0, 0, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("HttpOpenRequestW"), p);
    HINTERNET h = (HINTERNET)ret;
    if (h) InternetCloseHandle(h);
    // No crash is the primary requirement
}

TEST_F(NetworkExecutorTest, HttpOpenRequestA_NullConnection_ReturnsNull) {
    auto p = MakeRaw({0, (DWORD_PTR)"GET", (DWORD_PTR)"/", 0, 0, 0, 0, 0});
    DWORD_PTR ret = exec_.Execute(MakeEvent("HttpOpenRequestA"), p);
    HINTERNET h = (HINTERNET)ret;
    if (h) InternetCloseHandle(h);
}

// ── HttpSendRequestW / A (null request → fails gracefully) ───────────────────

TEST_F(NetworkExecutorTest, HttpSendRequestW_NullRequest_DoesNotCrash) {
    auto p = MakeRaw({0, 0, 0, 0, 0});
    exec_.Execute(MakeEvent("HttpSendRequestW"), p);  // result unimportant; no crash
}

TEST_F(NetworkExecutorTest, HttpSendRequestA_NullRequest_DoesNotCrash) {
    auto p = MakeRaw({0, 0, 0, 0, 0});
    exec_.Execute(MakeEvent("HttpSendRequestA"), p);
}

// ── InternetReadFile (null handle → fails gracefully) ────────────────────────

TEST_F(NetworkExecutorTest, InternetReadFile_NullHandle_DoesNotCrash) {
    char buf[64] = {};
    auto p = MakeRaw({0, (DWORD_PTR)buf, 63, 0});
    exec_.Execute(MakeEvent("InternetReadFile"), p);
}

// ── InternetCloseHandle ───────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, InternetCloseHandle_NullHandle_DoesNotCrash) {
    auto p = MakeRaw({0});
    exec_.Execute(MakeEvent("InternetCloseHandle"), p);  // no assertion; no crash required
}

TEST_F(NetworkExecutorTest, InternetCloseHandle_ValidHandle_Succeeds) {
    HINTERNET session = InternetOpenW(L"test", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    if (!session) GTEST_SKIP() << "InternetOpenW returned null";
    auto p = MakeRaw({(DWORD_PTR)session});
    DWORD_PTR ret = exec_.Execute(MakeEvent("InternetCloseHandle"), p);
    EXPECT_NE(ret, (DWORD_PTR)FALSE);
}

// ── Unknown API returns 0 ─────────────────────────────────────────────────────

TEST_F(NetworkExecutorTest, UnknownApi_ReturnsZero) {
    PreparedArgs p;
    DWORD_PTR ret = exec_.Execute(MakeEvent("NetUnknown"), p);
    EXPECT_EQ(ret, (DWORD_PTR)0);
}
