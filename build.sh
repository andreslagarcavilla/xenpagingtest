# Too lazy for a Makefile. This builds a 32 bit executable with libxenctrl statically-linked
XENPATH=/repos/xen-unstable.hg/

gcc  -O1 -fno-omit-frame-pointer -m32 -march=i686 -g -fno-strict-aliasing -std=gnu99 -Wall -Wstrict-prototypes -Wdeclaration-after-statement   -D__XEN_TOOLS__ -MMD -MF .unit_test.o.d  -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -fno-optimize-sibling-calls -mno-tls-direct-seg-refs -I${XENPATH}/tools/libxc -I${XENPATH}/tools/include -Werror -Wno-unused -g -o unit_test unit_test.c -ldl ${XENPATH}/tools/libxc/libxenctrl.a -lpthread

