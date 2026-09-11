#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "sample/scenarios.h"

static void Usage(const char* prog) {
    printf("Usage:\n");
    printf("  %s --scenario <name> [--scenario <name> ...]\n", prog);
    printf("  %s --all\n", prog);
    printf("Scenarios: file, registry, network, process\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) { Usage(argv[0]); return 1; }

    bool runAll = false;
    std::vector<std::string> scenarios;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--all") == 0) {
            runAll = true;
        } else if (std::strcmp(argv[i], "--scenario") == 0 && i + 1 < argc) {
            scenarios.push_back(argv[++i]);
        }
    }

    if (runAll) {
        scenarios = { "file", "registry", "network", "process" };
    }

    if (scenarios.empty()) { Usage(argv[0]); return 1; }

    int failedScenarios = 0;
    for (const auto& name : scenarios) {
        int result = 0;
        if      (name == "file")     result = RunFileScenario();
        else if (name == "registry") result = RunRegistryScenario();
        else if (name == "network")  result = RunNetworkScenario();
        else if (name == "process")  result = RunProcessScenario();
        else {
            printf("[ERROR] Unknown scenario: %s\n", name.c_str());
            ++failedScenarios;
            continue;
        }
        if (result > 0) ++failedScenarios;
    }

    printf("\n[SUMMARY] Exit code: %d\n", failedScenarios);
    return failedScenarios;
}
