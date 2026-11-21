.PHONY: build build-sanitize run clean

AFLCC = afl-clang-fast
FLAGS =

build:
	$(AFLCC) -Wall -Wextra $(FLAGS) ./*.c -o ./harness

run:
	afl-fuzz -i ./input -o out2 ./harness @@

clean:
	rm -rf ./harness ./harness.dSYM ./harness-asan ./harness-asan.dSYM
    
