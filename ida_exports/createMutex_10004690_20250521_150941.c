// --- Metadata ---
// Function Name: createMutex_10004690
// Address: 0x10004690
// Exported At: 20250521_150941
// Signature: unknown_signature
// ---------------
int createMutex_10004690()
{
  HANDLE v0; // esi

  v0 = CreateMutexA(0, 1, "MsWinZonesCacheCounterMutexA");
  if ( !v0 || GetLastError() != 183 )
    return 0;
  CloseHandle(v0);
  return 1;
}
