// --- Metadata ---
// Function Name: AES_EncryptDecrypt_403A77
// Address: 0x403A77
// Exported At: 20250515_220527
// Signature: unknown_signature
// ---------------
unsigned int __thiscall AES_EncryptDecrypt_403A77(int this, void *RawData, int outputBuffer, int datalength, int mode)
{
  unsigned int v6; // ecx
  unsigned __int8 *v7; // edi
  unsigned int result; // eax
  _BYTE *v9; // ebx
  unsigned int v10; // ecx
  bool v11; // zf
  _BYTE *v12; // edi
  _BYTE *v13; // ebx
  unsigned int v14; // ecx
  unsigned int v15; // ecx
  char pExceptionObject[12]; // [esp+Ch] [ebp-Ch] BYREF
  unsigned int encryptORdecrypta; // [esp+2Ch] [ebp+14h]
  unsigned int encryptORdecryptb; // [esp+2Ch] [ebp+14h]

  if ( !*(this + 4) )
  {
    exception::exception(pExceptionObject, &off_40F570);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  if ( !datalength || (v6 = *(this + 972), datalength % v6) )
  {
    exception::exception(pExceptionObject, &off_40F574);
    CxxThrowException(pExceptionObject, &_TI1_AVexception__);
  }
  if ( mode == 1 )                              // 암호화 
  {
    v7 = RawData;
    result = datalength / v6;
    encryptORdecrypta = 0;
    v9 = outputBuffer;
    if ( datalength / v6 )
    {
      do
      {
        AES_BlockTransform_encrypt_403797(this, v7, v9);
        XOR_Block_403A28(this, v9, (this + 1008));
        memcpy((this + 1008), v7, *(this + 972));
        v10 = *(this + 972);
        result = datalength / v10;
        v7 += v10;
        v9 += v10;
        ++encryptORdecrypta;
      }
      while ( encryptORdecrypta < datalength / v10 );
    }
  }
  else                                          // 복호화 
  {
    v11 = mode == 2;
    v12 = RawData;
    encryptORdecryptb = 0;
    v13 = outputBuffer;
    if ( v11 )
    {
      result = datalength / v6;
      if ( datalength / v6 )
      {
        do
        {
          AES_BlockTransform_decrypt_40350F(this, (this + 1008), v13);
          XOR_Block_403A28(this, v13, v12);
          memcpy((this + 1008), v12, *(this + 972));
          v14 = *(this + 972);
          result = datalength / v14;
          v12 += v14;
          v13 += v14;
          ++encryptORdecryptb;
        }
        while ( encryptORdecryptb < datalength / v14 );
      }
    }
    else
    {
      result = datalength / v6;
      if ( datalength / v6 )
      {
        do
        {
          AES_BlockTransform_encrypt_403797(this, v12, v13);
          v15 = *(this + 972);
          v12 += v15;
          result = datalength / v15;
          v13 += v15;
          ++encryptORdecryptb;
        }
        while ( encryptORdecryptb < datalength / v15 );
      }
    }
  }
  return result;
}
