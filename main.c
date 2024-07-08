#include <windows.h>
#include <wincred.h>
#include <process.h>

#pragma comment(lib, "credui.lib")


static void ProcessCmdLine(wchar_t** const lpCmdLine, wchar_t** const lpUsername) {
	while (iswspace(**lpCmdLine))
		*(*lpCmdLine)++ = L'\0';
	if (**lpCmdLine == L'"')
		*(*lpCmdLine)++ = L'\0';
	*lpUsername = *lpCmdLine;
	while (**lpCmdLine != L'"' && **lpCmdLine != L'\0')
		(*lpCmdLine)++;
	if (**lpCmdLine == L'"')
		*(*lpCmdLine)++ = L'\0';
	while (iswspace(**lpCmdLine))
		*(*lpCmdLine)++ = L'\0';
}

static void ErrorMessage(wchar_t* function, DWORD error) {
	LPWSTR message = NULL;
	FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)&message,
		0,
		NULL
	);
	// With NULL as parent window, the message both that appears
	// after credentials dialog, is brought to background.
	MessageBoxW(GetForegroundWindow(), message, function, MB_OK | MB_ICONERROR);
	LocalFree(message);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
	DWORD dwErr;

	LPWSTR nameInput;
	ProcessCmdLine(&lpCmdLine, &nameInput);
	if (nameInput[0] == L'\0' || lpCmdLine[0] == L'\0') {
		MessageBoxW(
			NULL,
			L"\"username\" C:\\Program Files\\Vendor\\Program.exe /param pam-pam",
			L"Command line format",
			MB_OK | MB_ICONQUESTION);
		return 100;
	}

	for (;;) {
		CREDUI_INFO credUi;
		ZeroMemory(&credUi, sizeof(credUi));
		credUi.cbSize = sizeof(credUi);
		credUi.hwndParent = NULL;
		credUi.pszCaptionText = L"Run as";
		credUi.pszMessageText = lpCmdLine;
		credUi.hbmBanner = NULL;
		ULONG authPackage = 0;  // Should we look it up by name?
		LPVOID outAuth;
		ULONG outAuthSize;
		BYTE inAuth[512];
		ULONG inAuthSize = sizeof(inAuth);
		CredPackAuthenticationBufferW(0, nameInput, L"", inAuth, &inAuthSize);
		dwErr = CredUIPromptForWindowsCredentialsW(
			&credUi, 0, &authPackage,
			inAuth, inAuthSize,
			&outAuth, &outAuthSize,
			NULL,
			CREDUIWIN_GENERIC | CREDUIWIN_IN_CRED_ONLY);
		if (dwErr != NO_ERROR) {
			ErrorMessage(L"CredUIPromptForWindowsCredentials", dwErr);
			if (dwErr == ERROR_CANCELLED) {
				return 0;
			}
			continue;
		}
		wchar_t name[CREDUI_MAX_USERNAME_LENGTH + 1] = L"";
		wchar_t domain[CREDUI_MAX_USERNAME_LENGTH + 1] = L"";
		wchar_t password[CREDUI_MAX_PASSWORD_LENGTH + 1] = L"";
		DWORD nameLen = ARRAYSIZE(name);
		DWORD domainLen = ARRAYSIZE(domain);
		DWORD passwordLen = ARRAYSIZE(password);
		CredUnPackAuthenticationBufferW(
			0,  // Flags
			outAuth, outAuthSize,
			name, &nameLen,
			domain, &domainLen,
			password, &passwordLen);
		SecureZeroMemory(outAuth, outAuthSize);
		CoTaskMemFree(outAuth);

		STARTUPINFO startup;
		PROCESS_INFORMATION process;
		ZeroMemory(&startup, sizeof(startup));
		startup.cb = sizeof(startup);
		ZeroMemory(&process, sizeof(process));
		// CreateProcessWithTokenW or CreateProcessW after ImpersonateLoggedOnUser
		// require SE_ASSIGNPRIMARYTOKEN_NAME and SE_INCREASE_QUOTA_NAME privileges.
		if (!CreateProcessWithLogonW(
			name, domain, password,
			LOGON_WITH_PROFILE,
			NULL, lpCmdLine,
			CREATE_NO_WINDOW,
			NULL, NULL, &startup, &process)) {
			ErrorMessage(L"CreateProcessWithLogonW", GetLastError());
			continue;
		}
		CloseHandle(process.hProcess);
		CloseHandle(process.hThread);
		return 0;
	}
}
