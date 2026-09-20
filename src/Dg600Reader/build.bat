@echo off
setlocal
cd /d "%~dp0"
set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo Khong tim thay trinh bien dich C# 32-bit: %CSC%
  exit /b 1
)
if not exist bin mkdir bin
"%CSC%" /nologo /platform:x86 /target:winexe /utf8output /out:bin\Dg600Reader.exe /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:Microsoft.CSharp.dll /reference:System.Core.dll Program.cs MainForm.cs DeviceClient.cs Models.cs CsvExport.cs NameStore.cs
if errorlevel 1 exit /b 1
echo Build OK: %~dp0bin\Dg600Reader.exe
endlocal
