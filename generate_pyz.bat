@echo off
pushd %~dp0
python -m zipapp -c -o mitigate.pyz -p "/usr/bin/sudo python" src/
popd
