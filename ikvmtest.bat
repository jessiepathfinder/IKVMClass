@echo off
getUnixTime.bat
set TEST_BEGIN=%ERRORLEVEL%
built-ikvm\bin\ikvm.exe -Xextremeoptimize -jar dacapo-9.12-MR1-bach.jar %1
set TEST_RESULT=%ERRORLEVEL%
getUnixTime.bat
set TEST_END=%ERRORLEVEL%
rmdir scratch
%TEST_RESULT% EQU 0 goto pass
appveyor AddTest -Name %1 -Framework IKVMTest -FileName built-ikvm\bin\ikvm.exe -Outcome Failed
goto end
:pass
appveyor AddTest -Name %1 -Framework IKVMTest -FileName built-ikvm\bin\ikvm.exe -Outcome Passed
:end
exit /b 0