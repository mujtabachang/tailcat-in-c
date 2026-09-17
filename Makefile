.PHONY: configure build test clean
configure:
	cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
build: configure
	cmake --build build -j
test: build
	ctest --test-dir build --output-on-failure
clean:
	cmake -E rm -rf build
