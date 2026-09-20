@echo off
REM Dang ky Standalone SDK 32-bit (zkemkeeper). Chay bang quyen Administrator.
setlocal
set "SDK=%~dp0..\requirements\Standalone-SDK\Communication Protocol SDK(32Bit Ver6.2.4.11)\sdk"
if not exist "%SDK%\zkemkeeper.dll" (
  echo Khong tim thay zkemkeeper.dll trong:
  echo %SDK%
  exit /b 1
)
set "DEST=%WINDIR%\SysWOW64"
echo Copy DLL sang %DEST%
copy /Y "%SDK%\*.dll" "%DEST%\" >nul
echo Dang ky zkemkeeper.dll 32-bit
"%WINDIR%\SysWOW64\regsvr32.exe" /s "%DEST%\zkemkeeper.dll"
if errorlevel 1 (
  echo Dang ky that bai. Hay chay file nay bang Run as administrator.
  exit /b 1
)
echo Dang ky SDK thanh cong.
endlocal
