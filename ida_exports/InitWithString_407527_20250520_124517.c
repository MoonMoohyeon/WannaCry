// --- Metadata ---
// Function Name: InitWithString_407527
// Address: 0x407527
// Exported At: 20250520_124517
// Signature: unknown_signature
// ---------------
_DWORD *__thiscall InitWithString_407527(_DWORD *this, char *Str)
{
  size_t v3; // eax
  char *v4; // eax

  this[1] = -1;                                 // 일반적인 문자열 기반 객체 초기화
  this[77] = -1;
  *this = 0;
  this[78] = 0;
  this[79] = 0;
  if ( Str )
  {
    v3 = strlen(Str);
    v4 = operator new(v3 + 1);
    this[78] = v4;
    strcpy(v4, Str);
  }
  return this;
}
