// --- Metadata ---
// Function Name: DeleteCriticalSection_10003A60
// Address: 0x10003A60
// Exported At: 20250522_123908
// Signature: unknown_signature
// ---------------
void __thiscall DeleteCriticalSection_10003A60(char *this)
{
  *(_DWORD *)this = &off_1000720C;
  DeleteCriticalSection((LPCRITICAL_SECTION)(this + 16));
}
