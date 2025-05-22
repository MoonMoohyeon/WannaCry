// --- Metadata ---
// Function Name: RunTaskdl_10005300
// Address: 0x10005300
// Exported At: 20250522_170428
// Signature: unknown_signature
// ---------------
DWORD __stdcall RunTaskdl_10005300(LPVOID lpThreadParameter)
{
  if ( isImportKeySuccess_1000DD8C )            // 키를 성공적으로 가져왔으면 taskdl 실행 
    return 0;
  do
  {
    RunProcessWithTimeout_10001080("taskdl.exe", 0xFFFFFFFF, 0);
    Sleep(30000u);
  }
  while ( !isImportKeySuccess_1000DD8C );
  return 0;
}
