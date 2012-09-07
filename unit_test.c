#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <xenctrl.h>
#include <xen/mem_event.h>
#include <sys/mman.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "xenctrlosdep.h"
#include <sys/ioctl.h>
#include <xc_private.h>

void sigint_handler(int sig)
{
    exit(0);
}

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define DIE(_f, _a...)          \
do {                            \
    fprintf(stderr, _f, ## _a);  \
    exit(1);                    \
} while(0)

#define PAGES   16

uint32_t domid;
int paging_port;
xc_interface *xch;
xc_evtchn *xcevt;

/* This is a separate thread which will be trying some mapping operations. */
void mapper_cleanup(void)
{
    xc_interface_close(xch);
}

static inline void map_check(xen_pfn_t *arr, unsigned int count, 
                            char *matches, int mode)
{
    int i, rc, err[PAGES];
    char *page;
    void *map_buf;

    if (mode == 0)
        map_buf = xc_map_foreign_bulk(xch, domid, PROT_READ, arr, err, count);
    else
        map_buf = xc_map_foreign_batch(xch, domid, PROT_READ, arr, count);

    if (map_buf == NULL)
        DIE("Could not map %u pages errno %d\n", count, errno);

    if (mode == 0)
        for (i = 0; i < count; i++)
            if (err[i])
                DIE("Mapping of frame %d:%lx had err %d\n",
                    i, arr[i], err[i]);

    for (i = 0, page = map_buf; 
            i < count; 
            i++, page += PAGE_SIZE)
    {
        char match = matches[i];
        int j;
        for (j = 0; j < PAGE_SIZE; j++)
        {
            char c = page[j];
            if (c != match)
                DIE("Frame %d:%lx char %d did not match %c:%d (%c:%d)\n",
                    i, arr[i], j, match, (int) match, c, (int) c);
        }
    }

    rc = munmap(map_buf, count * PAGE_SIZE);
    if (rc)
        DIE("Could not munmap %u pages rc %d errno %d\n",
            count, rc, errno);
}

static inline void map_and_retry(xen_pfn_t *arr,
                unsigned int count, char *matches, int mode)
{
    /* Map twice, first time should page in, second it should not. */
    map_check(arr, count, matches, mode);
    map_check(arr, count, matches, mode);
}

#define map_and_retry_bulk(a, c, m) map_and_retry(a, c, m, 0)
#define map_and_retry_batch(a, c, m) map_and_retry(a, c, m, 1)

static inline int batch_v2_ioctl(const xen_pfn_t *arr, int *err, unsigned int num)
{
    unsigned int i;
    int _errno, rc, fd = (int) xch->ops_handle;
    privcmd_mmapbatch_v2_t ioctlx;
    void *addr;

    addr = mmap(NULL, (unsigned long)num * PAGE_SIZE, PROT_READ, 
                MAP_SHARED, fd, 0);
    if ( addr == MAP_FAILED )
        DIE("Mmap (%u) failed errno %d\n", num, errno);

    ioctlx.num = num;
    ioctlx.dom = domid;
    ioctlx.addr = (unsigned long)addr;
    ioctlx.arr = arr;
    ioctlx.err = err;

    rc = ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH_V2, &ioctlx);
    _errno = errno;
    munmap(addr, num * PAGE_SIZE);

    if ((rc == 0) || ((rc == -1) && (_errno == ENOENT)))
        return (rc == 0) ? 0 : _errno;

    for (i = 0; i < num; i++)
        fprintf(stderr, "Frame %u:%lx -> %d\n",
                    i, arr[i], err[i]);
    DIE("Unexpected ioctl (%u) error rc %d errno %d", 
            num, rc, errno);
    return 0;
}

void mapper(int fd, unsigned long *arr, char *matches)
{
    int err[3], rc, i = 0;

    read(fd, &domid, sizeof(uint32_t));
    read(fd, &i, sizeof(int));
    close(fd);
    if (i != 1)
        DIE("Child did not get the right signal from parent\n");

    atexit(mapper_cleanup);

    xch = xc_interface_open(NULL, NULL, 0);
    if (xch == NULL)
        DIE("Could not open libxc handle (%d)\n", errno);

    /* Populate pfn 1 */
    map_and_retry_bulk(arr + 1, 1, matches + 1);

    /* Map pfn 0 and 1, should populate 0 */
    map_and_retry_bulk(arr, 2, matches);

    /* Map pfn 2 and 3, should populate both */
    map_and_retry_bulk(arr + 2, 2, matches + 2);

    /* Map a yes-no-yes pattern, the one in the middle should work */
    map_and_retry_bulk(arr + 5, 1, matches + 5);
    map_and_retry_bulk(arr + 3, 3, matches + 3);

    /* Now switch to manual */
    rc = batch_v2_ioctl(arr + 7, err, 1);
    if ((rc != ENOENT) || (err[0] != -ENOENT))
        DIE("Unmatched rc %d err %d\n", rc, err[0]);
    map_check(arr + 7, 1, matches + 7, 0);

    rc = batch_v2_ioctl(arr + 6, err, 2);
    if ((rc != ENOENT) || (err[0] != -ENOENT) || (err[1] != 0))
        DIE("Unmatched rc %d err[0] %d err[1] %d\n",
            rc, err[0], err[0]);
    map_check(arr + 6, 2, matches + 6, 0);

    /* Switch to batch testing */
    arr = arr + 10;
    matches = matches + 10;
    /* Populate pfn 1 */
    map_and_retry_batch(arr + 1, 1, matches + 1);
    /* Map pfn 0 and 1, should populate 0 */
    map_and_retry_batch(arr, 2, matches);
    /* Map pfn 2 and 3, should populate both */
    map_and_retry_batch(arr + 2, 2, matches + 2);
    /* Map a yes-no-yes pattern, the one in the middle should work */
    map_and_retry_batch(arr + 5, 1, matches + 5);
    map_and_retry_batch(arr + 3, 3, matches + 3);
}

void cleanup(void)
{
    xc_mem_paging_disable(xch, domid);
    xc_evtchn_unbind(xcevt, paging_port);
    xc_evtchn_close(xcevt);
    xc_domain_destroy(xch, domid);
    xc_interface_close(xch);
}

int main(int argc, char *argv[])
{
    uint32_t remote_port;
    int i, pending_port, rc, pipe_fd[2];
    xen_domain_handle_t handle = {0};
    unsigned long hap_alloc_mb = 1;
    unsigned long pfn, frames_array[PAGES];
    char matches[PAGES];
    xen_pfn_t _pfn;
    void *buf;
    pid_t child;

    mem_event_back_ring_t paging_ring;
    mem_event_sring_t *ring_mmap = NULL;

    for (i = 0; i < PAGES; i++)
    {
        frames_array[i] = i;
        matches[i] = (char) i;
    }

    rc = pipe(pipe_fd);
    if (rc)
        DIE("Could not create pipe\n");
    child = fork();
    if (child == -1)
        DIE("Could not fork\n");

    if (child == 0)
    {
        close(pipe_fd[1]);
        mapper(pipe_fd[0], frames_array, matches);
        exit(0);
    } else {
        close(pipe_fd[0]);
    }

    atexit(cleanup);
    signal(SIGINT, sigint_handler);

    posix_memalign(&buf, PAGE_SIZE, PAGE_SIZE);
    if (buf == NULL)
        DIE("COuld not allocate buffer page\n");

    xch = xc_interface_open(NULL, NULL, 0);
    if (xch == NULL)
        DIE("Could not open libxc handle (%d)\n", errno);

    xcevt = xc_evtchn_open(NULL, 0);
    if (xcevt == NULL)
        DIE("Could not open event channel handle (%d)\n", errno);

    rc = xc_domain_create(xch,
                          0,
                          handle, /* user-supplied context value. ignored. */
                          XEN_DOMCTL_CDF_hvm_guest | 
                          XEN_DOMCTL_CDF_oos_off |
                          XEN_DOMCTL_CDF_hap,
                          &domid);
    if( rc )
        DIE("Failed to create dummy domain. rc %d errno %d",
            rc, errno);
    printf("Created domain %u\n", domid);

    /* set the max vcpus to get a vcpu. This is needed so we can set the shadow
     * allocation so we can get ept so we can get p2m. */
    rc = xc_domain_max_vcpus(xch, domid, 1);
    if( rc )
        DIE("Failed to give domain a vcpu. rc %d errno %d",
             rc, errno);

    /* set the initial max allocation of this domain. PAGES, plus a few extra
     * for the paging ring, and wiggle room. In KiB. */
    rc = xc_domain_setmaxmem(xch, domid, (PAGES + 4) * 4);
    if( rc )
        DIE("Failed to set initial maxmem for domain. rc %d errno %d",
             rc, errno);

    rc = xc_shadow_control(xch, domid,
                           XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION,
                           NULL, 0, &hap_alloc_mb, 0, NULL);
    if( rc )
        DIE("Error setting shadow allocation. rc = %d errno = %d\n", 
             rc, errno);

    /* Populate PAGES */
    rc = xc_domain_populate_physmap_exact(xch, domid, PAGES, 0, 0, frames_array);
    if ( rc )
        DIE("Could not populate %d frames rc %d errno %d\n", PAGES, rc, errno);

    /* Now that the domain is populated, set up the paging ring */
    /* This magic stolen from xc_build_hvm. */
#define SPECIALPAGE_PAGING   0
#define NR_SPECIAL_PAGES     8
#define special_pfn(x) (0xff000u - NR_SPECIAL_PAGES + (x))
#define PAGING_RING_PFN_MAGIC   (special_pfn(SPECIALPAGE_PAGING)) 
    pfn = PAGING_RING_PFN_MAGIC;
    rc = xc_set_hvm_param(xch, domid, HVM_PARAM_PAGING_RING_PFN, 
                            (uint64_t) pfn);
    if ( rc )
        DIE("Could not set up paging ring pfn (%lx) param rc %d errno %d\n",
                pfn, rc, errno);

    rc = xc_domain_populate_physmap_exact(xch, domid, 1, 0, 0, &pfn);
    if ( rc )
        DIE("Could not populate paging ring pfn %lx rc %d errno %d\n", 
                pfn, rc, errno);

    _pfn = (xen_pfn_t) pfn;
    ring_mmap = xc_map_foreign_batch(xch, domid,
                                          PROT_READ | PROT_WRITE,
                                          &_pfn, 1);
    if (ring_mmap == NULL)
        DIE("Could not map paging ring pfn %lx errno %d\n",
                pfn, errno);

    SHARED_RING_INIT(ring_mmap);
    BACK_RING_INIT(&paging_ring, ring_mmap, PAGE_SIZE);
    
    rc = xc_mem_paging_enable(xch, domid, &remote_port);
    if ( rc )
        DIE("could not enable paging rc %d errno %d\n",
            rc, errno);
    
    /* Try to remove from physmap so it's not visible to the actual guest. */
    xc_domain_decrease_reservation_exact(xch, domid, 1, 0, &pfn);
    
    paging_port = xc_evtchn_bind_interdomain(xcevt, domid, remote_port);
    if (paging_port == -1)
        DIE("Could not bind remote event channel port %u errno %d",
            remote_port, errno);

    /* Page it all out */
    for (i = 0; i < PAGES; i++)
    {
        rc = xc_mem_paging_nominate(xch, domid, frames_array[i]);
        if ( rc )
            DIE("Paging nominate i %d pfn %lx rc %d errno %d\n", 
                    i, frames_array[i], rc, errno);

        rc = xc_mem_paging_evict(xch, domid, frames_array[i]);
        if ( rc )
            DIE("Paging evict i%d pfn %lx rc %d errno %d\n", 
                    i, frames_array[i], rc, errno);
    }

    /* Tell the child we are ready to go. nvm errors. */
    i = 1;
    write(pipe_fd[1], &domid, sizeof(uint32_t));
    write(pipe_fd[1], &i, sizeof(int));
    close(pipe_fd[1]);

    /* Now sit tight */
    while (1)
    {
        pending_port = xc_evtchn_pending(xcevt);
        if (pending_port != paging_port)
            DIE("Wrong event channel (%d) kicked (expected %d)\n",
                pending_port, paging_port);

        rc = xc_evtchn_unmask(xcevt, paging_port);
        if (rc)
            DIE("Could not unmask event channel rc %d errno %d\n",
                rc, errno);

        while( RING_HAS_UNCONSUMED_REQUESTS(&paging_ring) )
        {
            mem_event_request_t req;
            mem_event_response_t rsp;
            RING_IDX req_cons;
            RING_IDX rsp_prod;

            req_cons = paging_ring.req_cons;

            /* Copy request */
            memcpy(&req, RING_GET_REQUEST(&paging_ring, req_cons), sizeof(req));
            req_cons++;

            /* Update ring */
            paging_ring.req_cons = req_cons;
            paging_ring.sring->req_event = req_cons + 1;
            
            pfn = req.gfn;
            printf("Requested page in of pfn %lx\n", pfn);

            memset(buf, matches[pfn], PAGE_SIZE);
            rc = xc_mem_paging_load(xch, domid, pfn, buf);
            if ( rc )
                DIE("Page in of pfn %lx failed rc %d errno %d",
                        pfn, rc, errno);

            /* Manufacture identical response */
            rsp.gfn     = req.gfn;
            rsp.vcpu_id = req.vcpu_id;
            rsp.flags   = req.flags;
            rsp.p2mt    = req.p2mt;
            rsp_prod = paging_ring.rsp_prod_pvt;

            /* Copy response */
            memcpy(RING_GET_RESPONSE(&paging_ring, rsp_prod), &rsp, sizeof(rsp));
            rsp_prod++;

            /* Update ring */
            paging_ring.rsp_prod_pvt = rsp_prod;
            RING_PUSH_RESPONSES(&paging_ring);

            /* Kick back */
            rc = xc_evtchn_notify(xcevt, paging_port);
            if ( rc )
                DIE("Could not kick back paging port rc %d errno %d\n",
                    rc, errno);
        }
    }

    return 0;
}
