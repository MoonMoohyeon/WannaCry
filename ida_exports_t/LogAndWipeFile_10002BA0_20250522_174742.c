// --- Metadata ---
// Function Name: LogAndWipeFile_10002BA0
// Address: 0x10002BA0
// Exported At: 20250522_174742
// Signature: unknown_signature
// ---------------
void __thiscall LogAndWipeFile_10002BA0(int context, wchar_t *filePath)
{
  int v4; // edi
  _DWORD *prevNode; // edi
  _DWORD *nextNode; // ebp
  _DWORD *newNode; // eax
  _DWORD *v8; // ecx
  _DWORD *v9; // ecx
  char v10; // al
  const WCHAR *v11; // esi
  char v12[4]; // [esp+Ch] [ebp-1Ch] BYREF
  wchar_t *S1; // [esp+10h] [ebp-18h]
  int v14; // [esp+14h] [ebp-14h]
  int v15; // [esp+18h] [ebp-10h]
  int v16; // [esp+24h] [ebp-4h]
  struct _RTL_CRITICAL_SECTION *Stringa; // [esp+2Ch] [ebp+4h]

  if ( filePath )                               // filePath가 존재하거나 NULL인지에 따라 파일을 삭제하거나, 연결 리스트에 새 항목을 추가하고 기존 파일을 덮어쓰는 로직 
  {
    if ( !wcslen((const wchar_t *)(context + 1804)) )
      WipeFileWithRandomOrPattern_10003010(filePath, context + 4);
    Stringa = (struct _RTL_CRITICAL_SECTION *)(context + 1260);
    EnterCriticalSection((LPCRITICAL_SECTION)(context + 1260));
    v12[0] = context - 20;
    S1 = 0;
    v14 = 0;
    v15 = 0;
    v4 = wcslen(filePath);
    if ( (unsigned __int8)std::wstring::_Grow(v12, v4, 1) )
    {
      wmemcpy(S1, filePath, v4);
      v14 = v4;
      S1[v4] = 0;
    }
    prevNode = *(_DWORD **)(context + 1252);
    v16 = 0;
    nextNode = (_DWORD *)prevNode[1];
    newNode = operator new(0x18u);
    v8 = prevNode;
    if ( !prevNode )
      v8 = newNode;
    *newNode = v8;
    v9 = nextNode;
    if ( !nextNode )
      v9 = newNode;
    newNode[1] = v9;
    prevNode[1] = newNode;
    *(_DWORD *)newNode[1] = newNode;
    WStringAssign_10003810((int)(newNode + 2), v12);
    ++*(_DWORD *)(context + 1256);
    if ( S1 )
    {
      v10 = *((_BYTE *)S1 - 1);
      if ( v10 && v10 != -1 )
      {
        *((_BYTE *)S1 - 1) = v10 - 1;
        LeaveCriticalSection(Stringa);
        return;
      }
      operator delete(S1 - 1);
    }
    LeaveCriticalSection(Stringa);
  }
  else
  {
    v11 = (const WCHAR *)(context + 1804);
    if ( wcslen((const wchar_t *)(context + 1804)) )
      DeleteFileW_0(v11);
  }
}
