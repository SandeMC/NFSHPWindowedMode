#include "external/hooking/Hooking.Patterns.h"
#include "external/inireader/IniReader.h"
#include "external/injector/include/injector/injector.hpp"
#include <injector/assembly.hpp>
#include <windows.h>
#include <mutex>

void Init()
{
        auto pattern = hook::pattern("33 C0 83 C4 ? 38 47");
        if (!pattern.empty())
        {
            injector::WriteMemory<uint8_t>(pattern.get_first(5),  0x31, true);
            injector::WriteMemory<uint8_t>(pattern.get_first(6),  0xC0, true);
            injector::WriteMemory<uint8_t>(pattern.get_first(7),  0x40, true);
            injector::WriteMemory<uint8_t>(pattern.get_first(8),  0x89, true);
            injector::WriteMemory<uint8_t>(pattern.get_first(9),  0x46, true);
            injector::WriteMemory<uint8_t>(pattern.get_first(10), 0x20, true);
            injector::WriteMemory<uint8_t>(pattern.get_first(11), 0x90, true);
            injector::WriteMemory<uint8_t>(pattern.get_first(12), 0x90, true);
            injector::WriteMemory<uint8_t>(pattern.get_first(13), 0x90, true);
        }
        {
            auto pattern = hook::pattern("57 8D 54 24 ? 52 FF 15");
            if (!pattern.empty())
            {
                injector::WriteMemory<uint8_t>(pattern.get_first(6),  0x83, true);
                injector::WriteMemory<uint8_t>(pattern.get_first(7),  0xC4, true);
                injector::WriteMemory<uint8_t>(pattern.get_first(8),  0x0C, true);
                injector::WriteMemory<uint8_t>(pattern.get_first(9),  0x90, true);
                injector::WriteMemory<uint8_t>(pattern.get_first(10), 0x90, true);
                injector::WriteMemory<uint8_t>(pattern.get_first(11), 0x90, true);
            }
        }

        {
            auto pattern = hook::pattern("8B 54 24 ? 52 50 51 E8");
            if (!pattern.empty())
            {
                injector::WriteMemory<uint8_t>(pattern.get_first(0), 0x31, true);
                injector::WriteMemory<uint8_t>(pattern.get_first(1), 0xD2, true);
                injector::WriteMemory<uint8_t>(pattern.get_first(2), 0x90, true);
                injector::WriteMemory<uint8_t>(pattern.get_first(3), 0x90, true);
            }
        }

        {
            auto pattern = hook::pattern("75 ? 6A ? 50 FF 15");
            if (!pattern.empty())
            {
                injector::WriteMemory<uint8_t>(pattern.get_first(0), 0x90, true);
                injector::WriteMemory<uint8_t>(pattern.get_first(1), 0x90, true);
            }
        }

        {
            auto pattern = hook::pattern("75 ? 8B 4E ? 6A ? 51 FF 15");
            if (!pattern.empty())
            {
                injector::WriteMemory<uint8_t>(pattern.get_first(0), 0x90, true);
                injector::WriteMemory<uint8_t>(pattern.get_first(1), 0x90, true);
            }
        }

        {
            auto pattern = hook::pattern("6A ? 6A ? 6A ? 6A ? 6A ? 6A ? 50 FF 15");
            if (!pattern.empty())
            {
                injector::WriteMemory<uint8_t>(pattern.get_first(1), 0x21, true);
            }
        }
}

extern "C" __declspec(dllexport) void InitializeASI()
{
    static std::once_flag init_flag;
    std::call_once(init_flag, []() { Init(); });
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        InitializeASI();
    }
    return TRUE;
}