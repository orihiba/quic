@echo off

pushd zip
del /Q *
popd

for %%i in (%*) do copy %%i zip

del zip.zip
powershell.exe -nologo -noprofile -command "& { Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.ZipFile]::CreateFromDirectory('zip', 'zip.zip'); }"