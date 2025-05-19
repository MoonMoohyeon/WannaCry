// --- Metadata ---
// Function Name: AESKeyStruct_Release_4013CE
// Address: 0x4013CE
// Exported At: 20250519_150247
// Signature: unknown_signature
// ---------------
int __thiscall AESKeyStruct_Release_4013CE(HGLOBAL *this)
{
  _BYTE *v2; // eax
  int v3; // edi
  int v4; // ecx
  _BYTE *v5; // eax

  ReleaseCryptContext_4018B9(this + 1);         // 2개의 암호화 컨텍스트를 해제
  ReleaseCryptContext_4018B9(this + 11);
  v2 = this[306];
  v3 = 0x100000;
  if ( v2 )                                     // 두 개의 AES 키 혹은 중요한 메모리 블록을 0으로 덮은 후 해제 (디스크에 남지 않게끔 secure delete)
  {
    v4 = 0x100000;
    do
    {
      *v2++ = 0;
      --v4;
    }
    while ( v4 );
    GlobalFree(this[306]);
    this[306] = 0;
  }
  v5 = this[307];
  if ( v5 )
  {
    do
    {
      *v5++ = 0;
      --v3;
    }
    while ( v3 );
    GlobalFree(this[307]);
    this[307] = 0;
  }
  return 1;
}
