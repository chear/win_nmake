@echo off
start cmd /k ".\vc_env\NMAKE.exe /f makefile.mak clean all test"