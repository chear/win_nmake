
!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

PWD=.\
!IF "$(PATH)" == ""
PWD=$(PATH) 
!ENDIF 




###########################################   Var Defination ##############################################################
PROJECT_NAME=ap_mac_generator
IDE_PATH=D:\Program Files (x86)\Microsoft Visual Studio
VAR=$(IDE_PATH)\VC98\Bin\VCVARS32.BAT
#INCLUDE_PATH=$(IDE_PATH)\VC98\Include
#LIB_PATH=$(IDE_PATH)\VC98\Lib
INCLUDE_PATH=.\Include
LIB_PATH=.\vc_env\Lib
###########################################   Var Defination ##############################################################

CL=.\vc_env\CL.EXE 
#CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /FR"$(INTDIR)\\" /Fp"$(INTDIR)\MD5C.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_PROJ2=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /FR"$(INTDIR)\\" /Fp"$(INTDIR)\$(PROJECT_NAME).pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /I"$(INCLUDE_PATH)" /c

OUTDIR=.\Generator
INTDIR=.\Generator
OUTDIR=.\Generator


ALL : "$(OUTDIR)\$(PROJECT_NAME).exe" "$(OUTDIR)\$(PROJECT_NAME).bsc"


CLEAN :
	-@echo "cleaning ...."
	-@erase "$(INTDIR)\$(PROJECT_NAME).OBJ"
	-@erase "$(INTDIR)\$(PROJECT_NAME).SBR"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\$(PROJECT_NAME).exe"
	-@erase "$(OUTDIR)\$(PROJECT_NAME).bsc"
	-@erase "$(OUTDIR)\$(PROJECT_NAME).pch"
	-@erase "$(OUTDIR)\*.txt"
	-@erase "$(OUTDIR)\*.svc"
	-@erase ".\a.tmp"
	-@erase ".\aa.tmp"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

 
BSC32=.\vc_env\bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\$(PROJECT_NAME).bsc" 
BSC32_SBRS= \
	"$(INTDIR)\$(PROJECT_NAME).SBR"

"$(OUTDIR)\$(PROJECT_NAME).bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

#
# add file as following:
# SOURCE=.\file1.c file2.c
# 
SOURCE=.\ap_mac_generator.c


"$(INTDIR)\ap_mac_generator.OBJ" : $(SOURCE) "$(INTDIR)"


LINK32=.\vc_env\link.exe
LINK32_FLAGS=/libpath:"$(LIB_PATH)\" kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\$(PROJECT_NAME).pdb" /machine:I386 /out:"$(OUTDIR)\$(PROJECT_NAME).exe" 

LINK32_OBJS= \
	"$(INTDIR)\ap_mac_generator.obj"

"$(OUTDIR)\$(PROJECT_NAME).exe" : "$(OUTDIR)" $(LINK32_OBJS)
    $(LINK32) @<<
	$(LINK32_FLAGS) $(LINK32_OBJS)
<<

.c{$(INTDIR)}.obj::
   $(CL) @<<
   $(CPP_PROJ2) $< 
<<
 
 
###########################################   Test Script ##############################################################
 
APP_NAME=sample.exe
SAMPLE_FLAGS=/libpath:"$(LIB_PATH)" kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\H2_pdt_tool.pdb" /machine:I386 /out:"$(OUTDIR)\$(APP_NAME)" 

sample1:  "$(OUTDIR)" 
	-@echo "make a sample app"
	$(LINK32) @<<
	$(SAMPLE_FLAGS) $(INTDIR)\sample.obj
<<KEEP
	
test:sample_test_argc9

	
sample_test_argc10:
	$(INTDIR)\$(PROJECT_NAME).exe $(INTDIR)\test.svc 4 048B42281181 048B42281183 8202020052000001 WHA2320-E1C jiangsu admin 5

	
sample_test_argc9:
	$(INTDIR)\$(PROJECT_NAME).exe $(INTDIR)\test1.svc 1 048B42281181 048B42281197 8202020052000001 WHA2320-E1C admin 5


#
# building tmp files, export CL_FLAGS to .\a.tmp,
# LINK_FLAGS to .\aa.tmp , then can use ".\vc_env\CL.exe @.\a.tmp" or ".\vc_env\LINK.exe @.\aa.tmp" 
# to seprater debug.
mk_tmp: "$(OUTDIR)"
	-@echo $(CPP_PROJ2) $(SOURCE) > .\a.tmp
	-@echo $(LINK32_FLAGS) $(LINK32_OBJS) > .\aa.tmp
	
##########################################   Test Script ##############################################################