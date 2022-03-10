#include "perfsmpl.h"

#include <poll.h>
#include <fcntl.h>
#include <pthread.h>
#include <numaif.h>
#include <numa.h>
#include <sched.h>


perfsmpl *psmpl;
pthread_mutex_t sample_mutex;

void signal_thread_handler(int sig, siginfo_t *info, void *extra)
{
    // unsigned int myCpu, myNuma;
    // if(getcpu(&myCpu, &myNuma) != 0){
    //     std::cerr << "getcpu failed" << std::endl; return;
    // }
    // std::cout << "cpu " << myCpu << " processing samples" << std::endl;


    // Block incoming signals
    sigset_t blocksig;
    sigemptyset(&blocksig);
    sigaddset(&blocksig,SIGIO);
    sigprocmask(SIG_BLOCK,&blocksig,NULL);

    // Process
    pthread_mutex_lock(&sample_mutex);
    psmpl->process_sample_buffer();
    pthread_mutex_unlock(&sample_mutex);

    // Unblock
    sigprocmask(SIG_UNBLOCK,&blocksig,NULL);
}

perfsmpl::perfsmpl()
{
    // Defaults
    mmap_pages = 1;
    sample_period = 4000;
    sample_threshold = 7;
    pgsz = sysconf(_SC_PAGESIZE);
    mmap_size = (mmap_pages+1)*pgsz;
    pgmsk = mmap_pages*pgsz-1;

    ret = 0;
    ready = 0;
    stop = 0;

    mPID = 0;
    handler_fn_defined = 0;
    end_fn_defined = 0;

    collected_samples = 0;
    lost_samples = 0;
}

perfsmpl::~perfsmpl()
{
    close(fd);
    munmap(mmap_buf,mmap_size);
}

void perfsmpl::init_attr()
{
    // event attr
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.size = sizeof(struct perf_event_attr);

    pe.mmap = 1;
    pe.mmap_data = 1;
    pe.comm = 1;
    pe.disabled = 1;
    pe.exclude_user = 0;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 0;
    pe.exclude_idle = 0;
    pe.exclude_host = 0;
    pe.exclude_guest = 1;
    pe.pinned = 0;
    pe.sample_id_all = 0;
    pe.wakeup_events = 1;

    pe.sample_period = sample_period;
    pe.freq = 0;

    if(mode == SMPL_MEMORY)
    {
        // TODO: look this up in libpfm
        pe.type = PERF_TYPE_RAW;
        //0x100B - 100H Nehalem
        //0x5101cd - sandy bridge and newer
        //0xD005 - cooper lake
        pe.config = 0x5101cd;
        pe.config1 = sample_threshold; // ldlat
        pe.sample_type =
            PERF_SAMPLE_IP |
            //PERF_SAMPLE_CALLCHAIN |
            PERF_SAMPLE_ID |
            PERF_SAMPLE_STREAM_ID |
            PERF_SAMPLE_TIME |
            PERF_SAMPLE_TID |
            PERF_SAMPLE_PERIOD |
            PERF_SAMPLE_CPU |
            PERF_SAMPLE_ADDR |
            PERF_SAMPLE_WEIGHT |
            PERF_SAMPLE_DATA_SRC;
        pe.precise_ip = 2;
    }

    if(mode == SMPL_INSTRUCTIONS)
    {
        pe.type = PERF_TYPE_HARDWARE;
        pe.config = PERF_COUNT_SW_DUMMY;
        pe.sample_type =
            PERF_SAMPLE_IP |
            //PERF_SAMPLE_CALLCHAIN |
            PERF_SAMPLE_ID |
            PERF_SAMPLE_STREAM_ID |
            PERF_SAMPLE_TIME |
            PERF_SAMPLE_TID |
            PERF_SAMPLE_PERIOD |
            PERF_SAMPLE_CPU;
    }
}

int perfsmpl::init_perf()
{
    // Create attr according to sample mode
    fd = syscall(__NR_perf_event_open, &pe,mPID,-1,-1,0);

    if(fd == -1)
    {
        perror("perf_event_open");
        //cat /proc/sys/kernel/perf_event_paranoid -> set to -1
        return 1;
    }

    // Create mmap buffer for samples
    mmap_buf = (struct perf_event_mmap_page*)
        mmap(NULL, mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

    if(mmap_buf == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }

    return 0;
}

int perfsmpl::init_sighandler()
{
    psmpl = this;
    pthread_mutex_init(&sample_mutex, NULL);

    // Set up signal handler
    struct sigaction sact;
    memset(&sact, 0, sizeof(sact));
    sact.sa_sigaction = &signal_thread_handler;
    sact.sa_flags = SA_SIGINFO;

    int ret = sigaction(SIGIO, &sact, NULL);
    if(ret)
    {
        perror("sigaction");
        return 1;
    }

    sigset_t sold, snew;
    sigemptyset(&sold);
    sigemptyset(&snew);
    sigaddset(&snew, SIGIO);

    ret = sigprocmask(SIG_SETMASK, NULL, &sold);
    if(ret)
    {
        perror("sigaction");
        return 1;
    }

	if(sigismember(&sold, SIGIO))
    {
		ret = sigprocmask(SIG_UNBLOCK, &snew, NULL);
        if(ret)
        {
            perror("sigaction");
            return 1;
        }
    }//--> check if SIGIO is in current set; if yes, remove it (SIG_UNBLOCK)

    // Set perf event fd to signal
    ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0)|O_ASYNC);
    if(ret)
    {
        perror("fcntl");
        return 1;
    }
    ret = fcntl(fd, F_SETSIG, SIGIO);
    if(ret)
    {
        perror("fcntl");
        return 1;
    }
    ret = fcntl(fd, F_SETOWN, getpid());
    if(ret)
    {
        perror("fcntl");
        return 1;
    }

    return 0;
}

int perfsmpl::prepare(pid_t p)
{
    mPID = p;

    init_attr();

    ret = init_perf();
    if(ret != 0)
    {
        ready = 0;
        return ret;
    }

    ret = init_sighandler();
    if(ret != 0)
    {
        ready = 0;
        return ret;
    }

    ready = 1;

    return 0;
}

int perfsmpl::begin_sampler()
{
    if(!ready)
    {
        std::cerr << "Not ready to begin sampling!" << std::endl;
        return -1;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    return ret;
}

void perfsmpl::end_sampler()
{
    stop = 1;

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    read(fd, &counter_value, sizeof(uint64_t));

    process_sample_buffer(); // flush out remaining samples

    if(end_fn_defined)
    {
        end_fn(end_fn_args);
    }
}

int perfsmpl::process_single_sample(struct perf_event_mmap_page *mmap_buf)
{
    collected_samples++;

    // Fill up our sample
    memset(&pes,0,sizeof(pes));

    if(has_attribute(PERF_SAMPLE_IP))
    {
        read_mmap_buffer(mmap_buf,(char*)&pes.ip,sizeof(uint64_t));
    }

    if(has_attribute(PERF_SAMPLE_TID))
    {
        read_mmap_buffer(mmap_buf,(char*)&pes.pid,sizeof(uint32_t));
        read_mmap_buffer(mmap_buf,(char*)&pes.tid,sizeof(uint32_t));
    }

    if(has_attribute(PERF_SAMPLE_TIME))
    {
        read_mmap_buffer(mmap_buf,(char*)&pes.time,sizeof(uint64_t));
    }

    if(has_attribute(PERF_SAMPLE_ADDR))
    {
        read_mmap_buffer(mmap_buf,(char*)&pes.addr,sizeof(uint64_t));
    }

    if(has_attribute(PERF_SAMPLE_ID))
    {
        read_mmap_buffer(mmap_buf,(char*)&pes.id,sizeof(uint64_t));
    }

    if(has_attribute(PERF_SAMPLE_STREAM_ID))
    {
        read_mmap_buffer(mmap_buf,(char*)&pes.stream_id,sizeof(uint64_t));
    }

    if(has_attribute(PERF_SAMPLE_CPU))
    {
        read_mmap_buffer(mmap_buf,(char*)&pes.cpu,sizeof(uint32_t));
        read_mmap_buffer(mmap_buf,(char*)&pes.res,sizeof(uint32_t));
    }

    if(has_attribute(PERF_SAMPLE_PERIOD))
    {
        read_mmap_buffer(mmap_buf,(char*)&pes.period,sizeof(uint64_t));
    }

    /*
    if(has_attribute(PERF_SAMPLE_CALLCHAIN))
    {
        read_mmap_buffer(mmap_buf,(char*)&pes.nr,sizeof(uint64_t));
        pes.ips = (uint64_t*)malloc(pes.nr*sizeof(uint64_t));
        read_mmap_buffer(mmap_buf,(char*)pes.ips,pes.nr*sizeof(uint64_t));
    }
    */

    if(has_attribute(PERF_SAMPLE_WEIGHT))
    {
        read_mmap_buffer(mmap_buf,(char*)&pes.weight,sizeof(uint64_t));
    }

    if(has_attribute(PERF_SAMPLE_DATA_SRC))
    {
        read_mmap_buffer(mmap_buf,(char*)&pes.data_src,sizeof(uint64_t));

        //get numa reqion of the variable
        int numa_n = -1;
        int ret=-100;
        if(has_attribute(PERF_SAMPLE_IP) && (pes.data_src & 0xF) > 2)
        {
            void* ptr_to_check = (void*)&(pes.ip);
            ret=move_pages(0 , 1, &ptr_to_check, NULL, &numa_n, 0);
            //ret=move_pages(0 , 1, (void**)&pes.ip, NULL, &numa_n, 0);
        }

        if(ret == 0)
            pes.numa_node = numa_n;
    }

    if(handler_fn_defined)
    {
        handler_fn(&pes,handler_fn_args);
    }

    return ret;
}

int perfsmpl::process_sample_buffer()
{
    struct perf_event_header ehdr;
    int ret;


    for(;;)
    {
        ret = read_mmap_buffer(mmap_buf,(char*)&ehdr,sizeof(ehdr));
        if(ret)
            return 0; // no more samples

        switch(ehdr.type)
        {
            case PERF_RECORD_SAMPLE:
                process_single_sample(mmap_buf);
                break;
            case PERF_RECORD_EXIT:
                process_exit_sample(mmap_buf);
                break;
            case PERF_RECORD_LOST:
                process_lost_sample(mmap_buf);
                break;
            case PERF_RECORD_THROTTLE:
                process_freq_sample(mmap_buf);
                break;
            case PERF_RECORD_UNTHROTTLE:
                process_freq_sample(mmap_buf);
                break;
            default:
                //std::cerr << "Unknown sample type ";
                //std::cerr << ehdr.type << std::endl;
                skip_mmap_buffer(mmap_buf,sizeof(ehdr));
        }
    }

}

int perfsmpl::read_mmap_buffer(struct perf_event_mmap_page *mmap_buf, char *out, size_t sz)
{
	char *data;
	unsigned long tail;
	size_t avail_sz, m, c;
	data = ((char *)mmap_buf)+sysconf(_SC_PAGESIZE);
	tail = mmap_buf->data_tail & pgmsk;
	avail_sz = mmap_buf->data_head - mmap_buf->data_tail;
	if (sz > avail_sz)
		return -1;
	c = pgmsk + 1 -  tail;
	m = c < sz ? c : sz;
	memcpy(out, data+tail, m);
	if ((sz - m) > 0)
		memcpy(out+m, data, sz - m);
	mmap_buf->data_tail += sz;

	return 0;
}

void perfsmpl::skip_mmap_buffer(struct perf_event_mmap_page *mmap_buf, size_t sz)
{
    if ((mmap_buf->data_tail + sz) > mmap_buf->data_head)
        sz = mmap_buf->data_head - mmap_buf->data_tail;

    mmap_buf->data_tail += sz;
}

void perfsmpl::process_lost_sample(struct perf_event_mmap_page *mmap_buf)
{
	struct { uint64_t id, lost; } lost;
	ret = read_mmap_buffer(mmap_buf,(char*)&lost,sizeof(lost));

	lost_samples += lost.lost;
}

void perfsmpl::process_exit_sample(struct perf_event_mmap_page *mmap_buf)
{
	struct { pid_t pid, ppid, tid, ptid; } grp;
	int ret;

	ret = read_mmap_buffer(mmap_buf,(char*)&grp,sizeof(grp));
}

void perfsmpl::process_freq_sample(struct perf_event_mmap_page *mmap_buf)
{
	struct { uint64_t time, id, stream_id; } thr;
	int ret;

	ret = read_mmap_buffer(mmap_buf,(char*)&thr, sizeof(thr));
}

const char* Mitos_hit_type(struct perf_event_sample *s)
{
    uint64_t lvl_bits = s->data_src >> PERF_MEM_LVL_SHIFT;

    if(lvl_bits & PERF_MEM_LVL_NA)
        return "Not Available";
    else if(lvl_bits & PERF_MEM_LVL_HIT)
        return "Hit";
    else if(lvl_bits & PERF_MEM_LVL_MISS)
        return "Miss";

    return "Invalid Data Source";
}

const char* Mitos_data_source(struct perf_event_sample *s)
{
    uint64_t lvl_bits = s->data_src >> PERF_MEM_LVL_SHIFT;

    if(lvl_bits & PERF_MEM_LVL_NA)
        return "Not Available";
    else if(lvl_bits & PERF_MEM_LVL_L1)
        return "L1";
    else if(lvl_bits & PERF_MEM_LVL_LFB)
        return "LFB";
    else if(lvl_bits & PERF_MEM_LVL_L2)
        return "L2";
    else if(lvl_bits & PERF_MEM_LVL_L3)
        return "L3";
    else if(lvl_bits & PERF_MEM_LVL_LOC_RAM)
        return "Local RAM";
    else if(lvl_bits & PERF_MEM_LVL_REM_RAM1)
        return "Remote RAM 1 Hop";
    else if(lvl_bits & PERF_MEM_LVL_REM_RAM2)
        return "Remote RAM 2 Hops";
    else if(lvl_bits & PERF_MEM_LVL_REM_CCE1)
        return "Remote Cache 1 Hops";
    else if(lvl_bits & PERF_MEM_LVL_REM_CCE2)
        return "Remote Cache 2 Hops";
    else if(lvl_bits & PERF_MEM_LVL_IO)
        return "I/O Memory";
    else if(lvl_bits & PERF_MEM_LVL_UNC)
        return "Uncached Memory";

    return "Invalid Data Source";
}
