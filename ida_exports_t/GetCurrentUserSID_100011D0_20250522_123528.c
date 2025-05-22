// --- Metadata ---
// Function Name: GetCurrentUserSID_100011D0
// Address: 0x100011D0
// Exported At: 20250522_123528
// Signature: unknown_signature
// ---------------
int __cdecl GetCurrentUserSID_100011D0(wchar_t *sidStringBuffer)
{
  HANDLE v1; // eax
  int result; // eax
  _DWORD *v3; // esi
  DWORD TokenInformationLength; // [esp+8h] [ebp-Ch] BYREF
  HANDLE TokenHandle; // [esp+Ch] [ebp-8h] BYREF
  wchar_t *sidString; // [esp+10h] [ebp-4h] BYREF

  TokenInformationLength = 0;
  v1 = GetCurrentProcess();
  result = OpenProcessToken(v1, 8u, &TokenHandle);// 사용자 SID를 버퍼에 저장 
  if ( result )
  {
    if ( GetTokenInformation(TokenHandle, TokenUser, 0, TokenInformationLength, &TokenInformationLength)
      || GetLastError() == 122 )
    {
      v3 = GlobalAlloc(0x40u, TokenInformationLength);
      result = GetTokenInformation(TokenHandle, TokenUser, v3, TokenInformationLength, &TokenInformationLength);
      if ( result )
      {
        result = (int)LoadLibraryA("advapi32.dll");
        if ( result )
        {
          result = (int)GetProcAddress((HMODULE)result, "ConvertSidToStringSidW");
          if ( result )
          {
            sidString = 0;
            result = ((int (__stdcall *)(_DWORD, wchar_t **))result)(*v3, &sidString);
            if ( result )
            {
              wcscpy(sidStringBuffer, sidString);
              if ( v3 )
                GlobalFree(v3);
              result = 1;
            }
          }
        }
      }
    }
    else
    {
      result = 0;
    }
  }
  return result;
}
