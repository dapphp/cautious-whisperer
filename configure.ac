AC_PREREQ([2.69])
AC_INIT([cs12final], [1.0.0], [drew@drew-phillips.com])
AC_CONFIG_SRCDIR([src/agency.asm])
#AC_CONFIG_HEADERS([])

AC_PROG_CC
AX_PROG_YASM

PACKAGE_CFLAGS="-c -nostdlib -fPIC -no-pie"
PACKAGE_LDFLAGS="-lc -lssl -lcrypto"
PACKAGE_YASMFLAGS="-Worphan-labels -f elf64"

AC_SUBST([PACKAGE_CFLAGS])
AC_SUBST([PACKAGE_LDFLAGS])
AC_SUBST([PACKAGE_YASMFLAGS])

AX_CHECK_OPENSSL

AC_ARG_VAR(ASFLAGS, Additional flags to pass to the assembler)
AC_ARG_VAR(PAD_PAGE_SIZE, The number of bytes per page in a pad)
AC_ARG_VAR(SALT_LEN, The number of bytes to use for cryptographic salts)
AC_ARG_VAR(PBKDF2_ITERATIONS, The number of iterations to perform for PBKDF2 key generation)

AS_VAR_IF(PAD_PAGE_SIZE, [], [
    AC_DEFINE([PAD_PAGE_SIZE], [125], [])
    AC_MSG_NOTICE([PAD_PAGE_SIZE not set...using default of 125 characters])
], [
    AC_DEFINE_UNQUOTED([PAD_PAGE_SIZE], [$PAD_PAGE_SIZE], [])
])

AS_VAR_IF(SALT_LEN, [], [
    AC_DEFINE([SALT_LEN], [8], [])
    AC_MSG_NOTICE([SALT_LEN not set...using default 8 bytes])
], [
    AC_DEFINE_UNQUOTED([SALT_LEN], [$SALT_LEN], [])
])

AS_VAR_IF(PBKDF2_ITERATIONS, [], [
    AC_DEFINE([PBKDF2_ITERATIONS], [256000], [])
    AC_MSG_NOTICE([Using default of 256000 for PBKDF2_ITERATIONS])
])

AM_INIT_AUTOMAKE(foreign)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
