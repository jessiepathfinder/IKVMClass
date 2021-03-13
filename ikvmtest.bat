@echo off
built-ikvm\bin\ikvm.exe -Xextremeoptimize -jar dacapo-9.12-MR1-bach.jar %1
set TEST_RESULT=%ERRORLEVEL%
rmdir /s /q scratch
if %TEST_RESULT% EQU 0 goto pass
appveyor AddTest -Name %1 -Framework IKVMTest -FileName built-ikvm\bin\ikvm.exe -Outcome Failed
goto end
:pass
appveyor AddTest -Name %1 -Framework IKVMTest -FileName built-ikvm\bin\ikvm.exe -Outcome Passed
:end
set ERRORLEVEL=0