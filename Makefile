.PHONY: build run clean

AFLCC = afl-clang-fast
FLAGS =

build:
	$(AFLCC) -Wall -Weverything ./*.c -fsanitize=fuzzer $(FLAGS) -o ./harness

run:
	afl-fuzz -i ./input -o out2 ./harness @@

clean:
	rm -rf ./harness ./harness.dSYM
    
