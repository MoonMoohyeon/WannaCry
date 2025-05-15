// --- Metadata ---
// Function Name: AESKeySchedule_402A76
// Address: 0x402A76
// Exported At: 20250515_230457
// Signature: unknown_signature
// ---------------
size_t __thiscall AESKeySchedule_402A76(int this, int keyvalue, void *Src, int keylength, size_t Size)
{
  int v6; // ecx
  int v7; // eax
  int v8; // eax
  int v9; // eax
  int v10; // eax
  int v11; // edx
  bool v12; // sf
  char *v13; // ebx
  int v14; // edx
  char *v15; // ebx
  int v16; // eax
  unsigned __int8 *v17; // ecx
  int v18; // edi
  int v19; // edx
  int *v20; // eax
  int v21; // ebx
  _BYTE *v22; // ecx
  int *v23; // ecx
  int v24; // edx
  int v25; // eax
  int v26; // eax
  int v27; // edx
  _DWORD *v28; // eax
  int v29; // ecx
  _DWORD *v30; // eax
  int v31; // ecx
  _DWORD *v32; // eax
  int v33; // ecx
  int *v34; // ecx
  int v35; // edi
  int v36; // edx
  int v37; // eax
  int v38; // eax
  int v39; // edx
  size_t result; // eax
  bool v41; // cc
  int v42; // ecx
  _DWORD *v43; // edi
  void *v44; // [esp-8h] [ebp-28h]
  size_t v45; // [esp-4h] [ebp-24h]
  char pExceptionObject[12]; // [esp+Ch] [ebp-14h] BYREF
  int v47; // [esp+18h] [ebp-8h]
  int v48; // [esp+1Ch] [ebp-4h]
  int keyvalueb; // [esp+28h] [ebp+8h]
  int keyvaluec; // [esp+28h] [ebp+8h]
  int keyvalued; // [esp+28h] [ebp+8h]
  int keyvaluea; // [esp+28h] [ebp+8h]

  if ( !keyvalue )                              // AES 키 스케줄 또는 암호화 상태 초기화 작업
  {
    Src = &unk_40F57C;
    exception::exception(pExceptionObject, &Src);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  v6 = keylength;
  if ( keylength != 16 && keylength != 24 && keylength != 32 )
  {
    Src = &unk_40F57C;
    exception::exception(pExceptionObject, &Src);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  if ( Size != 16 && Size != 24 && Size != 32 )
  {
    Src = &unk_40F57C;
    exception::exception(pExceptionObject, &Src);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  v45 = Size;
  *(this + 972) = Size;
  v44 = Src;
  *(this + 968) = v6;
  memcpy((this + 976), v44, v45);               // 버퍼에 키 복사 
  memcpy((this + 1008), Src, *(this + 972));
  v7 = *(this + 968);
  if ( v7 == 16 )
  {
    v10 = *(this + 972);
    if ( v10 == 16 )
      v9 = 10;
    else
      v9 = v10 != 24 ? 14 : 12;
  }
  else
  {
    if ( v7 != 24 )
    {
      *(this + 1040) = 14;                      // 라운드 수 결정 
      goto InitRoundState;
    }
    v8 = (*(this + 972) == 32) - 1;
    LOBYTE(v8) = v8 & 0xFE;
    v9 = v8 + 14;
  }
  *(this + 1040) = v9;
InitRoundState:
  v11 = 0;
  v12 = *(this + 1040) < 0;
  keylength = *(this + 972) / 4;
  if ( !v12 )
  {
    v13 = (this + 8);
    do
    {
      if ( keylength > 0 )
        memset(v13, 0, 4 * keylength);
      ++v11;
      v13 += 32;
    }
    while ( v11 <= *(this + 1040) );
  }
  v14 = 0;
  if ( *(this + 1040) >= 0 )
  {
    v15 = (this + 488);
    do
    {
      if ( keylength > 0 )
        memset(v15, 0, 4 * keylength);
      ++v14;
      v15 += 32;
    }
    while ( v14 <= *(this + 1040) );
  }
  v16 = *(this + 968) / 4;
  v17 = keyvalue;
  v18 = keylength * (*(this + 1040) + 1);
  v47 = v18;
  v19 = v16;
  v20 = (this + 1044);
  v48 = v19;
  if ( v19 > 0 )
  {
    Src = v19;
    do
    {
      v21 = *v17 << 24;
      v22 = v17 + 1;
      *v20 = v21;
      *v20 |= *v22++ << 16;
      LOBYTE(v21) = 0;
      BYTE1(v21) = *v22;
      *v20 |= v21;
      *v20 |= *++v22;
      v17 = v22 + 1;
      ++v20;
      Src = Src - 1;
    }
    while ( Src );
  }
  Src = 0;
  if ( v19 <= 0 )
  {
BeginKeyExpansionLoop:
    if ( Src < v18 )
    {
      Size = &unk_40BBFC;
      while ( 1 )
      {
        keyvaluec = *(this + 4 * v19 + 1040);
        *(this + 1044) ^= byte_4089FC[HIBYTE(keyvaluec)] ^ ((byte_4089FC[keyvaluec] ^ ((byte_4089FC[BYTE1(keyvaluec)] ^ ((*Size++ ^ byte_4089FC[BYTE2(keyvaluec)]) << 8)) << 8)) << 8);
        if ( v19 == 8 )
        {
          v30 = (this + 1048);
          v31 = 3;
          do
          {
            *v30 ^= *(v30 - 1);
            ++v30;
            --v31;
          }
          while ( v31 );
          keyvalued = *(this + 1056);
          v32 = (this + 1064);
          *(this + 1060) ^= byte_4089FC[keyvalued] ^ ((byte_4089FC[BYTE1(keyvalued)] ^ ((byte_4089FC[BYTE2(keyvalued)] ^ (byte_4089FC[HIBYTE(keyvalued)] << 8)) << 8)) << 8);
          v33 = 3;
          do
          {
            *v32 ^= *(v32 - 1);
            ++v32;
            --v33;
          }
          while ( v33 );
        }
        else if ( v19 > 1 )
        {
          v28 = (this + 1048);
          v29 = v19 - 1;
          do
          {
            *v28 ^= *(v28 - 1);
            ++v28;
            --v29;
          }
          while ( v29 );
        }
        keyvaluea = 0;
        if ( v19 > 0 )
          break;
FinishRoundKeyAssignment:
        if ( Src >= v18 )
          goto FinalizeKeySchedule;
      }
      v34 = (this + 1044);
      while ( Src < v18 )
      {
        v35 = Src / keylength;
        v36 = Src % keylength;
        *(this + 4 * (Src % keylength + 8 * (Src / keylength)) + 8) = *v34;
        v37 = *(this + 1040) - v35;
        ++keyvaluea;
        v18 = v47;
        v38 = v36 + 8 * v37;
        v39 = *v34++;
        Src = Src + 1;
        *(this + 4 * v38 + 488) = v39;
        v19 = v48;
        if ( keyvaluea >= v48 )
          goto FinishRoundKeyAssignment;
      }
    }
  }
  else
  {
    v23 = (this + 1044);
    while ( Src < v18 )
    {
      keyvalueb = Src / keylength;
      v24 = Src % keylength;
      *(this + 4 * (Src % keylength + 8 * (Src / keylength)) + 8) = *v23;
      v25 = *(this + 1040) - keyvalueb;
      Src = Src + 1;
      v26 = v24 + 8 * v25;
      v27 = *v23++;
      *(this + 4 * v26 + 488) = v27;
      v19 = v48;
      if ( Src >= v48 )
        goto BeginKeyExpansionLoop;
    }
  }
FinalizeKeySchedule:
  result = 1;
  v41 = *(this + 1040) <= 1;
  Size = 1;
  if ( !v41 )
  {
    Src = (this + 520);
    do
    {
      v42 = keylength;
      if ( keylength > 0 )
      {
        v43 = Src;
        do
        {
          *v43 = dword_40B7FC[*v43] ^ dword_40B3FC[BYTE1(*v43)] ^ dword_40AFFC[BYTE2(*v43)] ^ dword_40ABFC[HIBYTE(*v43)];
          ++v43;
          --v42;
        }
        while ( v42 );
      }
      ++Size;
      Src = Src + 32;
      result = Size;
    }
    while ( Size < *(this + 1040) );
  }
  *(this + 4) = 1;                              // 초기화 완료 플래그 
  return result;
}
