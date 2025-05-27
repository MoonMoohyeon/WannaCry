// --- Metadata ---
// Function Name: createRbNode_408DB0
// Address: 0x408DB0
// Exported At: 20250527_180045
// Signature: unknown_signature
// ---------------
_DWORD *__stdcall createRbNode_408DB0(int a1, int a2)
{
  _DWORD *result; // eax

  result = operator new(0x18u);
  result[1] = a1;
  result[5] = a2;
  return result;
}
