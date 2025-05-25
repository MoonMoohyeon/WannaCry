# WannaCry
워너크라이 정적 분석


export, import 스크립트를 통해 IDA Pro 디컴파일 코드 작업 결과를 파일로 내보내거나 가져옵니다.


ida_exports 폴더는 tasksche.exe의 분석 결과이며,
ida_exports_t 폴더는 tasksche.exe의 실행 중 동적으로 로드되는 t.wnry 파일 dll의 분석 결과입니다.


decrypt_AES.cpp
decrypt_large_chunk.py
extract_from_t.py
파일은 t.wnry 파일에서 암호화된 dll을 추출하는 과정입니다.
