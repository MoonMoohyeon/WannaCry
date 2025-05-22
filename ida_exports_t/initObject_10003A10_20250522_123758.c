// --- Metadata ---
// Function Name: initObject_10003A10
// Address: 0x10003A10
// Exported At: 20250522_123758
// Signature: unknown_signature
// ---------------
char *__thiscall initObject_10003A10(char *this)
{
  *((_DWORD *)this + 1) = 0;
  *((_DWORD *)this + 2) = 0;
  *((_DWORD *)this + 3) = 0;
  *(_DWORD *)this = &off_1000720C;
  InitializeCriticalSection((LPCRITICAL_SECTION)(this + 16));
  return this;
}
