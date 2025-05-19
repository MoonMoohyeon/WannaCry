// --- Metadata ---
// Function Name: AESKeyStruct_FinalCleanup_40137A
// Address: 0x40137A
// Exported At: 20250519_150319
// Signature: unknown_signature
// ---------------
void __thiscall AESKeyStruct_FinalCleanup_40137A(_DWORD *this)
{
  *this = &off_4081D8;                          // vtable 설정 
  AESKeyStruct_Release_4013CE(this);            // 리소스 해제 
  AESKeyStruct_initVtable_402A6F(this + 21);    // 하위 구조체 초기화 
  AESKeyStruct_Destructor_40181B(this + 44);    // 하위 구초제 파괴 
  AESKeyStruct_Destructor_40181B(this + 4);     // 실행 후 메모리에서 제거하고, 공개키로 암호화된 AES 키만 남김. 내부 메모리를 확실히 청소하려는 의도.
}
