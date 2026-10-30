@echo off
rem .NET 8 SDK gerekli: https://dotnet.microsoft.com/download/dotnet/8.0
dotnet publish -c Release -o publish
echo.
echo Hazir: publish\STRUD-Downloader.exe
pause
