#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include "WinRarConfig.hpp"
#include "WinRarKeygen.hpp"
#include <system_error>

void Help() {
    _putts(TEXT("Usage:"));
    _putts(TEXT("        winrar-keygen.exe <your name> <license type>"));
    _putts(TEXT(""));
    _putts(TEXT("Example:"));
    _putts(TEXT(""));
    _putts(TEXT("        winrar-keygen.exe \"Rebecca Morrison\" \"Single PC usage license\""));
    _putts(TEXT("  or:"));
    _putts(TEXT("        winrar-keygen.exe \"Rebecca Morrison\" \"Single PC usage license\" >> rarreg.key\n"));
}

void PrintRegisterInfo(PCTSTR lpszUserName, PCTSTR lpszLicenseType, const WinRarKeygen<WinRarConfig>::RegisterInfo& Info) {
    _tprintf_s(TEXT("%hs\n"), "RAR registration data");
    _tprintf_s(TEXT("%s\n"), lpszUserName);
    _tprintf_s(TEXT("%s\n"), lpszLicenseType);
    _tprintf_s(TEXT("UID=%hs\n"), Info.UID.c_str());
    for (size_t i = 0; i < Info.HexData.length(); i += 54) {
        _tprintf_s(TEXT("%.54hs\n"), Info.HexData.c_str() + i);
    }
}

std::string ToUTF8(PCSTR lpszAnsiString) {
    if (GetACP() != CP_UTF8) {
        int len = MultiByteToWideChar(CP_ACP, 0, lpszAnsiString, -1, NULL, 0);
        if (len == 0) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        std::wstring temp(len, '\x00');

        len = MultiByteToWideChar(CP_ACP, 0, lpszAnsiString, -1, temp.data(), static_cast<int>(temp.length()));
        if (len == 0) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        len = WideCharToMultiByte(CP_UTF8, 0, temp.c_str(), -1, NULL, 0, NULL, NULL);
        if (len == 0) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        std::string Result(len, '\x00');

        len = WideCharToMultiByte(CP_UTF8, 0, temp.c_str(), -1, Result.data(), static_cast<int>(Result.length()), NULL, NULL);
        if (len == 0) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        return Result;
    } else {
        return std::string(lpszAnsiString);
    }
}

std::string ToUTF8(PCWSTR lpszUnicodeString) {
    int len;

    len = WideCharToMultiByte(CP_UTF8, 0, lpszUnicodeString, -1, NULL, 0, NULL, NULL);
    if (len == 0) {
        auto err = GetLastError();
        throw std::system_error(err, std::system_category());
    }

    std::string Result(len, '\x00');

    len = WideCharToMultiByte(CP_UTF8, 0, lpszUnicodeString, -1, Result.data(), static_cast<int>(Result.length()), NULL, NULL);
    if (len == 0) {
        auto err = GetLastError();
        throw std::system_error(err, std::system_category());
    }

    return Result;
}

int _tmain(int argc, PTSTR argv[]) {
    if (argc == 3) {
        try {
            PrintRegisterInfo(
                argv[1],
                argv[2],
                WinRarKeygen<WinRarConfig>::GenerateRegisterInfo(ToUTF8(argv[1]).c_str(), ToUTF8(argv[2]).c_str())
            );
        } catch (std::exception& e) {
            _tprintf_s(TEXT("%hs\n"), e.what());
            return -1;
        }
    } else {
        Help();
    }
    return 0;
}

