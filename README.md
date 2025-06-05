# WannaCry
워너크라이 분석

export, import 스크립트를 통해 IDA Pro 디컴파일 코드 작업 결과를 파일로 내보내거나 가져옵니다.

ida_exports 폴더는 tasksche.exe의 분석 결과이며, ida_exports_m 폴더는 mssecsvc.exe의 분석 결과입니다.
ida_exports_t 폴더는 tasksche.exe의 실행 중 동적으로 로드되는 t.wnry 파일 dll의 분석 결과입니다.

4-1과 4-2는 t.wnry 파일에서 dll을 추출한 결과입니다.

5는 워너크라이 종류의 SSDEEP 해시값 매핑 결과이며, 6은 워너크라이와 MITRE가 제공하는 전체 데이터에 대한 TTPs 매핑 결과입니다.

7은 워너크라이에 대한 YARA와 SNORT룰입니다.

1, 2, 3은 발표에 사용한 자료와 문서형 산출물입니다.