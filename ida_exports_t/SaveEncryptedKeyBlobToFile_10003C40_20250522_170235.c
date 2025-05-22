// --- Metadata ---
// Function Name: SaveEncryptedKeyBlobToFile_10003C40
// Address: 0x10003C40
// Exported At: 20250522_170235
// Signature: unknown_signature
// ---------------
BYTE *__thiscall SaveEncryptedKeyBlobToFile_10003C40(int this, LPCSTR lpFileName)
{
  BYTE *result; // eax
  BYTE *v3; // ebx
  HANDLE v4; // eax
  void *v5; // esi
  DWORD Buffer; // [esp+8h] [ebp-8h] BYREF
  DWORD NumberOfBytesWritten; // [esp+Ch] [ebp-4h] BYREF

  Buffer = 0;
  NumberOfBytesWritten = 0;
  if ( !lpFileName )                            // 특정 데이터 조합으로 블롭 생성 
    return 0;
  result = EncryptKeyBlob_10004170(*(_DWORD *)(this + 4), *(_DWORD *)(this + 8), *(_DWORD *)(this + 12), 7u, &Buffer);
  v3 = result;
  if ( result )
  {
    v4 = CreateFileA(lpFileName, 0x40000000u, 1u, 0, 4u, 0x80u, 0);
    v5 = v4;
    if ( v4 != (HANDLE)-1 )
    {
      SetFilePointer(v4, 0, 0, 2u);
      WriteFile(v5, &Buffer, 4u, &NumberOfBytesWritten, 0);// 파일에 저장 
      WriteFile(v5, v3, Buffer, &NumberOfBytesWritten, 0);
    }
    GlobalFree(v3);                             // 리소스 정리 
    result = (BYTE *)(NumberOfBytesWritten == Buffer);
  }
  return result;
}
