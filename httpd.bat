@echo off
echo.
echo.
echo.
echo Open a web browser to:
echo.
echo http://localhost:9696
echo.
echo.
echo.
echo.
echo.
echo. 
echo.

rem edit the line below to set where your python.exe is

cd web
\python27\python.exe -u -m CGIHTTPServer 9696
