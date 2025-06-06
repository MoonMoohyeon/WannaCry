// --- Metadata ---
// Function Name: SetupCryptoSessionKey_10003AC0
// Address: 0x10003AC0
// Exported At: 20250526_164355
// Signature: unknown_signature
// ---------------
int __thiscall SetupCryptoSessionKey_10003AC0(_DWORD *this, LPCSTR pky, LPCSTR eky)
{
  HCRYPTKEY v5; // esi

  if ( !InitCryptoProvider_10003A80((char *)this) )
    goto LABEL_2;
  if ( pky )                                    // 암호화 컨텍스트(CSP, 세션키, 공개키)를 초기화하고, 세션키를 파일에서 불러오거나(복원), 없으면 새로 생성해서 파일에 저장한 뒤(내보내기), 필요시 추가 백업(a3)도 처리
  {
    if ( !SetKey_10003C00(this, pky) )
    {
      if ( !CryptImportKey(this[1], defaultPubKeyBlob_1000CF40, 276u, 0, 0, this + 3)
        || !CallLoadCryptographicAPI_10004350(this[1], (int)(this + 2))
        || !ExportKeyToFile_10004040(this[1], this[2], 6u, pky) )
      {
        goto LABEL_2;
      }
      if ( eky )
        SaveEncryptedKeyBlobToFile_10003C40((int)this, eky);
      if ( !SetKey_10003C00(this, pky) )
        goto LABEL_2;
    }
    v5 = this[3];
    if ( v5 )
      CryptDestroyKey(v5);
  }
  else if ( !CryptImportKey(this[1], builtinPubKeyBlob_1000D054, 276u, 0, 0, this + 2) )
  {
LABEL_2:
    ReleaseCryptoResources_10003BB0(this);
    return 0;
  }
  return 1;
}
