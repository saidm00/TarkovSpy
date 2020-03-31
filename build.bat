@echo off

if not exist build (
	md build
)

cd build
cmake .. -G"MSYS Makefiles"
make
cd ..