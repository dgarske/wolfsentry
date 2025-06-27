cls
make ^
    CC=d:/mingw/rx/4.8.2a/bin/gcc ^
    AR=d:/mingw/rx/4.8.2a/bin/ar ^
    STATIC=1 ^
    OPTIM=-O2 ^
    RUNTIME=ThreadX-NetXDuo ^
    THREADX_TOP=../../../bsp/xlogic/rx72n/ ^
    NEED_THREADX_TYPES=1 ^
    THREADX_TYPES_TOP=../../../bsp/src/common ^
    NETXDUO_TOP=../../../bsp/src/ethernet ^
    EXTRA_CFLAGS="-Bd:/mingw/rx/4.8.2a/bin -gstabs -g3 -std=gnu99 -mbig-endian-data -fno-leading-underscore -ftabstop=4 -fno-common -fno-use-linker-plugin -fno-leading-underscore -fstrict-volatile-bitfields -D_REENT_SMALL" ^
    C_WARNFLAGS="-Wdeclaration-after-statement -Wmissing-prototypes -Wnested-externs -Wredundant-decls -Wshadow -Wstrict-prototypes -Wundef -Wno-format -Wno-main -Wno-maybe-uninitialized -Wno-parentheses -Wno-strict-aliasing" ^
    V=1

REM d:/mingw/rx/4.8.2a/bin/gcc -Bd:/mingw/rx/4.8.2a/bin
REM d:/mingw/rx/4.8.2a/bin/objcopy.exe -I elf32-rx-be-ns
REM d:/mingw/rx/4.8.2a/bin/ld -Ld:/mingw/rx/4.8.2a/lib --warn-common --oformat=elf32-rx-be