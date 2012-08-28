@echo off

cd %~dp0

if /i "%1"=="help" goto help
if /i "%1"=="--help" goto help
if /i "%1"=="-help" goto help
if /i "%1"=="/help" goto help
if /i "%1"=="?" goto help
if /i "%1"=="-?" goto help
if /i "%1"=="--?" goto help
if /i "%1"=="/?" goto help

@rem Process arguments.
set config=Debug
set target=Build
set noprojgen=
set nobuild=
set test=
set test_args=
set msi=
set luvit=

:next-arg
if "%1"=="" goto args-done
if /i "%1"=="debug"        set config=Debug&goto arg-ok
if /i "%1"=="release"      set config=Release&goto arg-ok
if /i "%1"=="clean"        set target=Clean&goto arg-ok
if /i "%1"=="noprojgen"    set noprojgen=1&goto arg-ok
if /i "%1"=="nobuild"      set nobuild=1&goto arg-ok
if /i "%1"=="test"         set test=test&goto arg-ok
if /i "%1"=="msi"          set msi=1&goto arg-ok
:arg-ok
shift
goto next-arg



:gyp_install_failed
echo Failed to download gyp. Make sure you have subversion installed, or 
echo manually install gyp into %~dp0tools\gyp.
goto exit


:args-done


if exist tools\gyp goto project-gen
echo svn co http://gyp.googlecode.com/svn/trunk tools/gyp
svn co http://gyp.googlecode.com/svn/trunk tools/gyp
if errorlevel 1 goto gyp_install_failed
goto project-gen

:project-gen
@rem Skip project generation if requested.
if defined noprojgen goto msbuild

@rem Generate the VS project.
cmd /c "python tools\gyp.py -f msvs -G msvs_version=2010"
if errorlevel 1 goto create-msvs-files-failed
if not exist bsnmptools.sln goto create-msvs-files-failed
echo Project files generated.

:msbuild
@rem Skip project generation if requested.
if defined nobuild goto msi

@rem Bail out early if not running in VS build env.
if defined VCINSTALLDIR goto msbuild-found
if not defined VS100COMNTOOLS goto msbuild-not-found
if not exist "%VS100COMNTOOLS%\..\..\vc\vcvarsall.bat" goto msbuild-not-found
call "%VS100COMNTOOLS%\..\..\vc\vcvarsall.bat"
if not defined VCINSTALLDIR goto msbuild-not-found
goto msbuild-found

:msbuild-not-found
echo Build skipped. To build, this file needs to run from VS cmd prompt.
goto run

:msbuild-found
@rem Build the sln with msbuild.
msbuild bsnmptools.sln
if errorlevel 1 goto exit

:msi
@rem Skip msi generation if not requested
if not defined msi goto run
for /F "tokens=*" %%i in (version.txt) do set SNMP_VERSION=%%i
@rem add create installer code at here
if errorlevel 1 goto exit

:run
@rem Run tests if requested.
if "%test%"=="" goto exit

if "%config%"=="Debug" set test_args=--mode=debug
if "%config%"=="Release" set test_args=--mode=release

if "%test%"=="test" set test_args=%test_args%
goto exit

:create-msvs-files-failed
echo Failed to create vc project files. 
goto exit

:help
echo vcbuild.bat [debug/release] [msi] [test/test-simple] [clean] [noprojgen] [nobuild]
echo Examples:
echo   vcbuild.bat                : builds debug build
echo   vcbuild.bat test           : builds debug build and runs tests
goto exit

:exit



