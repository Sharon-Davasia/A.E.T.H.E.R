@echo off
rem Reproducible fixture build: in-box .NET Framework compiler only.
rem No downloads, no elevation, no execution-policy changes.
setlocal
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC%" (
  echo In-box .NET Framework compiler not found; fixture build unavailable. 1>&2
  exit /b 1
)
"%CSC%" /nologo /target:winexe /out:%~dp0AETHERFixture.exe /reference:System.Windows.Forms.dll /reference:System.Drawing.dll %~dp0AetherFixture.cs
if errorlevel 1 exit /b 1
echo Built %~dp0AETHERFixture.exe
endlocal
