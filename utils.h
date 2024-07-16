#pragma once

namespace utils {

    std::wstring RegGetString(HKEY hKey, const std::wstring& subKey, const std::wstring& value) {
        DWORD dataSize = 0;
        LONG retCode = ::RegGetValue(
            hKey, subKey.c_str(), value.c_str(), RRF_SUBKEY_WOW6464KEY | RRF_RT_REG_SZ, nullptr, nullptr, &dataSize);
        if (retCode != ERROR_SUCCESS || !dataSize) {
            return {};
        }

        std::wstring data(dataSize / sizeof(wchar_t), 0);
        retCode = ::RegGetValue(hKey,
                                subKey.c_str(),
                                value.c_str(),
                                RRF_SUBKEY_WOW6464KEY | RRF_RT_REG_SZ,
                                nullptr,
                                data.data(),
                                &dataSize);
        if (retCode != ERROR_SUCCESS) {
            return {};
        }

        return data;
    }

    // Helper to detour a function.
    template <typename TMethod>
    void DetourFunctionAttach(TMethod target, TMethod hooked, TMethod& original) {
        if (original) {
            // Already hooked.
            return;
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        original = target;
        DetourAttach((PVOID*)&original, hooked);

        DetourTransactionCommit();
    }

    template <typename TMethod>
    void DetourFunctionDetach(TMethod target, TMethod hooked, TMethod& original) {
        if (!original) {
            // Not hooked.
            return;
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourDetach((PVOID*)&original, hooked);

        DetourTransactionCommit();

        original = nullptr;
    }

    template <typename TMethod>
    void DetourDllAttach(const char* dll, const char* target, TMethod hooked, TMethod& original) {
        if (original) {
            // Already hooked.
            return;
        }

        HMODULE handle;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_PIN, dll, &handle);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        original = (TMethod)GetProcAddress(handle, target);
        DetourAttach((PVOID*)&original, hooked);

        DetourTransactionCommit();
    }

    template <typename TMethod>
    void DetourDllDetach(const char* dll, const char* target, TMethod hooked, TMethod& original) {
        if (!original) {
            // Not hooked.
            return;
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourDetach((PVOID*)&original, hooked);

        DetourTransactionCommit();

        original = nullptr;
    }

    // https://stackoverflow.com/questions/216823/how-to-trim-a-stdstring
    // trim from start (in place)
    template <typename T>
    inline void ltrim(std::basic_string<T>& s, T ch) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [&](T c) { return c != ch; }));
    }

    // trim from end (in place)
    template <typename T>
    inline void rtrim(std::basic_string<T>& s, T ch) {
        s.erase(std::find_if(s.rbegin(), s.rend(), [&](T c) { return c != ch; }).base(), s.end());
    }

    // trim from both ends (in place)
    template <typename T>
    inline void trim(std::basic_string<T>& s, T ch) {
        rtrim(s, ch);
        ltrim(s, ch);
    }

    template <typename T>
    static inline bool startsWith(const T& str, const T& substr) {
        return str.find(substr) == 0;
    }

    template <typename T>
    static inline bool endsWith(const T& str, const T& substr) {
        const auto pos = str.find(substr);
        return pos != T::npos && pos == str.size() - substr.size();
    }

} // namespace utils
