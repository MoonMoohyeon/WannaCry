// --- Metadata ---
// Function Name: DriveDetectionDecryption_10005730
// Address: 0x10005730
// Exported At: 20250522_104948
// Signature: unknown_signature
// ---------------
void __stdcall __noreturn DriveDetectionDecryption_10005730(LPVOID lpThreadParameter)
{
  DWORD v1; // ebp
  DWORD v2; // edi
  int v3; // esi
  HANDLE v4; // eax

  v1 = GetLogicalDrives();                      // 시스템의 논리 드라이브 변화를 감시하면서, 새로운 드라이브가 추가되면 해당 드라이브에 대해 복호화 스레드를 생성 
  if ( !isImportKeySuccess_1000DD8C )
  {
    while ( 1 )
    {
      Sleep(0xBB8u);
      v2 = v1;
      v1 = GetLogicalDrives();
      if ( v1 != v2 )
        break;
LABEL_10:
      if ( isImportKeySuccess_1000DD8C )
        goto LABEL_11;
    }
    v3 = 3;
    while ( !isImportKeySuccess_1000DD8C )
    {
      if ( (((v1 ^ v2) >> v3) & 1) != 0 && ((v2 >> v3) & 1) == 0 )
      {
        v4 = CreateThread(0, 0, decryptDrive_10005680, (LPVOID)v3, 0, 0);
        if ( v4 )
          CloseHandle(v4);
      }
      if ( ++v3 >= 26 )
        goto LABEL_10;
    }
  }
LABEL_11:
  ExitThread(0);
}
