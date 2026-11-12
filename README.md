# littlefs fuzzer

Mutational grey-box fuzzing harness for
[littlefs](<https://github.com/littlefs-project/littlefs>),
currently at commit
[6cb4e86540eca0d9ba62500a298385c9d863c8be](<https://github.com/littlefs-project/littlefs/commit/6cb4e86540eca0d9ba62500a298385c9d863c8be>).

## Building

Building is done with `./build-harness.sh`,
assuming a working `afl-clang-fast` install.
If this isn't present, please follow [AFL++'s install instructions](<https://aflplus.plus/docs/install/>).

## Fuzzing

This can be fine-tuned for other purposes,
but a fuzzing campaign using `N` number of cores can be started with `./start_campaign.sh N`.

