// --- Metadata ---
// Function Name: copyBufferedDataWithCallback_403BD6
// Address: 0x403BD6
// Exported At: 20250519_104309
// Signature: unknown_signature
// ---------------
int __cdecl copyBufferedDataWithCallback_403BD6(int circularBuffer, void *outputSTream, int a3)
{
  char *v4; // ecx
  unsigned int v5; // ebx
  size_t v6; // eax
  size_t v7; // ebx
  int (__cdecl *v8)(_DWORD, char *, size_t); // eax
  int v9; // eax
  char *v10; // eax
  char *v11; // ecx
  size_t v12; // eax
  size_t v13; // ebx
  int (__cdecl *v14)(_DWORD, char *, size_t); // eax
  int v15; // eax
  char *v17; // [esp+Ch] [ebp-4h]
  char *Srca; // [esp+1Ch] [ebp+Ch]

  v4 = *(circularBuffer + 48);                  // 원형 버퍼에서 데이터를 복사하고, 콜백으로 처리한 후 출력 버퍼에 전달하는 역할 
  v5 = *(circularBuffer + 52);
  v17 = *(outputSTream + 3);
  Srca = v4;
  if ( v4 > v5 )
    v5 = *(circularBuffer + 44);
  v6 = *(outputSTream + 4);
  v7 = v5 - v4;
  if ( v7 > v6 )
    v7 = *(outputSTream + 4);
  if ( v7 && a3 == -5 )
    a3 = 0;
  *(outputSTream + 5) += v7;
  *(outputSTream + 4) = v6 - v7;
  v8 = *(circularBuffer + 56);
  if ( v8 )
  {
    v9 = v8(*(circularBuffer + 60), v4, v7);
    *(circularBuffer + 60) = v9;
    *(outputSTream + 12) = v9;
  }
  if ( v7 )
  {
    memcpy(v17, Srca, v7);
    v17 += v7;
    Srca += v7;
  }
  v10 = *(circularBuffer + 44);
  if ( Srca == v10 )
  {
    v11 = *(circularBuffer + 40);
    Srca = v11;
    if ( *(circularBuffer + 52) == v10 )
      *(circularBuffer + 52) = v11;
    v12 = *(outputSTream + 4);
    v13 = *(circularBuffer + 52) - v11;
    if ( v13 > v12 )
      v13 = *(outputSTream + 4);
    if ( v13 && a3 == -5 )
      a3 = 0;
    *(outputSTream + 5) += v13;
    *(outputSTream + 4) = v12 - v13;
    v14 = *(circularBuffer + 56);
    if ( v14 )
    {
      v15 = v14(*(circularBuffer + 60), v11, v13);
      *(circularBuffer + 60) = v15;
      *(outputSTream + 12) = v15;
    }
    if ( v13 )
    {
      memcpy(v17, Srca, v13);
      v17 += v13;
      Srca += v13;
    }
  }
  *(outputSTream + 3) = v17;
  *(circularBuffer + 48) = Srca;
  return a3;
}
