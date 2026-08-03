@echo off
REM ==========================================================================
REM HexStrike AI - Build ^& Deploy (Windows CMD)
REM Dockerfiles/compose in deploy\ ; build CONTEXT = repo root.
REM
REM Usage:  scripts\build-deploy.bat ^<command^> [arg]
REM   build [latest^|predeploy^|postdeploy]   Build all 3, or one
REM   push  [latest^|predeploy^|postdeploy]   Push all, or one
REM   pull / up / down / logs / vps-up / vps-down / clean / help
REM Env: REGISTRY_IMAGE (default zed378/hexstrike-ai)
REM ==========================================================================
setlocal enabledelayedexpansion

REM repo root = parent of this script's dir
pushd "%~dp0.." || exit /b 1

if "%REGISTRY_IMAGE%"=="" set "REGISTRY_IMAGE=zed378/hexstrike-ai"
set "IMG_LATEST=%REGISTRY_IMAGE%:latest"
set "IMG_PRE=%REGISTRY_IMAGE%:predeploy"
set "IMG_POST=%REGISTRY_IMAGE%:postdeploy"
set "CDEV=deploy\docker-compose.yml"
set "CVPS=deploy\docker-compose.vps.yml"

set "ENVF="
if exist ".env" set "ENVF=--env-file .env"

set "CMD=%~1"
set "ARG=%~2"
if "%CMD%"=="" set "CMD=help"

if /i "%CMD%"=="build"    goto :build
if /i "%CMD%"=="push"     goto :push
if /i "%CMD%"=="pull"     goto :pull
if /i "%CMD%"=="up"       goto :up
if /i "%CMD%"=="down"     goto :down
if /i "%CMD%"=="logs"     goto :logs
if /i "%CMD%"=="vps-up"   goto :vpsup
if /i "%CMD%"=="vps-down" goto :vpsdown
if /i "%CMD%"=="clean"    goto :clean
goto :help

:build
if "%ARG%"=="" goto :build_all
if /i "%ARG%"=="latest"     ( docker build -f deploy\Dockerfile -t "%IMG_LATEST%" . & goto :done )
if /i "%ARG%"=="full"       ( docker build -f deploy\Dockerfile -t "%IMG_LATEST%" . & goto :done )
if /i "%ARG%"=="predeploy"  ( docker build -f deploy\Dockerfile.predeploy -t "%IMG_PRE%" . & goto :done )
if /i "%ARG%"=="postdeploy" ( docker build -f deploy\Dockerfile.postdeploy -t "%IMG_POST%" . & goto :done )
echo [ERROR] Unknown image: %ARG% & goto :fail
:build_all
docker build -f deploy\Dockerfile.predeploy  -t "%IMG_PRE%"    . || goto :fail
docker build -f deploy\Dockerfile.postdeploy -t "%IMG_POST%"   . || goto :fail
docker build -f deploy\Dockerfile            -t "%IMG_LATEST%" . || goto :fail
goto :done

:push
if "%ARG%"=="" (
  docker push "%IMG_LATEST%" ^& docker push "%IMG_PRE%" ^& docker push "%IMG_POST%"
) else if /i "%ARG%"=="predeploy" ( docker push "%IMG_PRE%"
) else if /i "%ARG%"=="postdeploy" ( docker push "%IMG_POST%"
) else ( docker push "%IMG_LATEST%" )
goto :done

:pull
docker pull "%IMG_LATEST%" ^& docker pull "%IMG_PRE%" ^& docker pull "%IMG_POST%"
goto :done

:up
docker compose %ENVF% -f "%CDEV%" pull
docker compose %ENVF% -f "%CDEV%" up -d hexstrike-server
goto :done
:down
docker compose %ENVF% -f "%CDEV%" down
goto :done
:logs
docker compose %ENVF% -f "%CDEV%" logs -f
goto :done
:vpsup
docker compose %ENVF% -f "%CVPS%" pull
docker compose %ENVF% -f "%CVPS%" up -d
goto :done
:vpsdown
docker compose %ENVF% -f "%CVPS%" down
goto :done
:clean
docker compose %ENVF% -f "%CDEV%" down --volumes 2>nul
docker rmi "%IMG_LATEST%" 2>nul
docker rmi "%IMG_PRE%" 2>nul
docker rmi "%IMG_POST%" 2>nul
goto :done

:help
echo HexStrike AI - Build ^& Deploy (Windows CMD)
echo(
echo   build [latest^|predeploy^|postdeploy]   Build all 3 images, or one
echo   push  [latest^|predeploy^|postdeploy]   Push all, or one
echo   pull / up / down / logs / vps-up / vps-down / clean / help
echo(
echo Env: REGISTRY_IMAGE (default zed378/hexstrike-ai)
goto :done

:fail
popd
endlocal
exit /b 1
:done
popd
endlocal
