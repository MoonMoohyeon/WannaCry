// --- Metadata ---
// Function Name: CryptoObject_Destructor_10001680
// Address: 0x10001680
// Exported At: 20250522_104505
// Signature: unknown_signature
// ---------------
void __thiscall CryptoObject_Destructor_10001680(char *this)
{
  _DWORD **v2; // ebp
  _DWORD *i; // ebx
  _DWORD **v4; // esi

  *(_DWORD *)this = &off_100071F8;              // 복합 객체의 소멸자 
  CleanupCryptoObject_10001760(this);
  v2 = (_DWORD **)*((_DWORD *)this + 313);
  for ( i = *v2; i != v2; --*((_DWORD *)this + 314) )
  {
    v4 = (_DWORD **)i;
    i = (_DWORD *)*i;
    *v4[1] = *v4;
    (*v4)[1] = v4[1];
    std::wstring::_Tidy(v4 + 2, 1);
    operator delete(v4);
  }
  operator delete(*((void **)this + 313));
  *((_DWORD *)this + 313) = 0;
  *((_DWORD *)this + 314) = 0;
  DestroyCryptoObject_10005DB0(this + 84);
  DeleteCriticalSection_10003A60(this + 44);
  DeleteCriticalSection_10003A60(this + 4);
}
