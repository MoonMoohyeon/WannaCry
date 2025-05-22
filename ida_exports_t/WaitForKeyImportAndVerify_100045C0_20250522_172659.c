// --- Metadata ---
// Function Name: WaitForKeyImportAndVerify_100045C0
// Address: 0x100045C0
// Exported At: 20250522_172659
// Signature: unknown_signature
// ---------------
void __stdcall __noreturn WaitForKeyImportAndVerify_100045C0(LPVOID lpThreadParameter)
{
  while ( 1 )
  {
    isImportKeySuccess_1000DD8C = importKeyAndVerify_10004500((int)lpThreadParameter);
    if ( isImportKeySuccess_1000DD8C )          // 네트워크나 외부 저장소 등에서 키가 도착할 때까지 기다리며, 주기적으로 키를 불러오고 검증하는 작업 
      break;
    Sleep(5000u);
  }
  ExitThread(0);
}
