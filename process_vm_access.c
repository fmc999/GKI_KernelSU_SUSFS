// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * linux/mm/process_vm_access.c
 *
 * Copyright (C) 2010-2011 Christopher Yeoh <cyeoh@au1.ibm.com>, IBM Corp.
 */

#include <linux/compat.h>
#include <linux/mm.h>
#include <linux/uio.h>
#include <linux/sched.h>
#include <linux/compat.h>
#include <linux/sched/mm.h>
#include <linux/highmem.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/io.h>
#include <asm/io.h>
/**
 * process_vm_rw_pages - read/write pages from task specified
 * @pages: array of pointers to pages we want to copy
 * @offset: offset in page to start copying from/to
 * @len: number of bytes to copy
 * @iter: where to copy to/from locally
 * @vm_write: 0 means copy from, 1 means copy to
 * Returns 0 on success, error code otherwise
 */
static int process_vm_rw_pages(struct page **pages,
			       unsigned offset,
			       size_t len,
			       struct iov_iter *iter,
			       int vm_write)
{
	/* Do the copy for each page */
	while (len && iov_iter_count(iter)) {
		struct page *page = *pages++;
		size_t copy = PAGE_SIZE - offset;
		size_t copied;

		if (copy > len)
			copy = len;

		if (vm_write)
			copied = copy_page_from_iter(page, offset, copy, iter);
		else
			copied = copy_page_to_iter(page, offset, copy, iter);

		len -= copied;
		if (copied < copy && iov_iter_count(iter))
			return -EFAULT;
		offset = 0;
	}
	return 0;
}

/* Maximum number of pages kmalloc'd to hold struct page's during copy */
#define PVM_MAX_KMALLOC_PAGES (PAGE_SIZE * 2)

/**
 * process_vm_rw_single_vec - read/write pages from task specified
 * @addr: start memory address of target process
 * @len: size of area to copy to/from
 * @iter: where to copy to/from locally
 * @process_pages: struct pages area that can store at least
 *  nr_pages_to_copy struct page pointers
 * @mm: mm for task
 * @task: task to read/write from
 * @vm_write: 0 means copy from, 1 means copy to
 * Returns 0 on success or on failure error code
 */
static int process_vm_rw_single_vec(unsigned long addr,
				    unsigned long len,
				    struct iov_iter *iter,
				    struct page **process_pages,
				    struct mm_struct *mm,
				    struct task_struct *task,
				    int vm_write)
{
	unsigned long pa = addr & PAGE_MASK;
	unsigned long start_offset = addr - pa;
	unsigned long nr_pages;
	ssize_t rc = 0;
	unsigned long max_pages_per_loop = PVM_MAX_KMALLOC_PAGES
		/ sizeof(struct pages *);
	unsigned int flags = 0;

	/* Work out address and page range required */
	if (len == 0)
		return 0;
	nr_pages = (addr + len - 1) / PAGE_SIZE - addr / PAGE_SIZE + 1;

	if (vm_write)
		flags |= FOLL_WRITE;

	while (!rc && nr_pages && iov_iter_count(iter)) {
		int pinned_pages = min(nr_pages, max_pages_per_loop);
		int locked = 1;
		size_t bytes;

		/*
		 * Get the pages we're interested in.  We must
		 * access remotely because task/mm might not
		 * current/current->mm
		 */
		mmap_read_lock(mm);
		pinned_pages = pin_user_pages_remote(mm, pa, pinned_pages,
						     flags, process_pages,
						     &locked);
		if (locked)
			mmap_read_unlock(mm);
		if (pinned_pages <= 0)
			return -EFAULT;

		bytes = pinned_pages * PAGE_SIZE - start_offset;
		if (bytes > len)
			bytes = len;

		rc = process_vm_rw_pages(process_pages,
					 start_offset, bytes, iter,
					 vm_write);
		len -= bytes;
		start_offset = 0;
		nr_pages -= pinned_pages;
		pa += pinned_pages * PAGE_SIZE;

		/* If vm_write is set, the pages need to be made dirty: */
		unpin_user_pages_dirty_lock(process_pages, pinned_pages,
					    vm_write);
	}

	return rc;
}

/* Maximum number of entries for process pages array
   which lives on stack */
#define PVM_MAX_PP_ARRAY_COUNT 16

/**
 * process_vm_rw_core - core of reading/writing pages from task specified
 * @pid: PID of process to read/write from/to
 * @iter: where to copy to/from locally
 * @rvec: iovec array specifying where to copy to/from in the other process
 * @riovcnt: size of rvec array
 * @flags: currently unused
 * @vm_write: 0 if reading from other process, 1 if writing to other process
 *
 * Returns the number of bytes read/written or error code. May
 *  return less bytes than expected if an error occurs during the copying
 *  process.
 */
static ssize_t process_vm_rw_core(pid_t pid, struct iov_iter *iter,
				  const struct iovec *rvec,
				  unsigned long riovcnt,
				  unsigned long flags, int vm_write)
{
	struct task_struct *task;
	struct page *pp_stack[PVM_MAX_PP_ARRAY_COUNT];
	struct page **process_pages = pp_stack;
	struct mm_struct *mm;
	unsigned long i;
	ssize_t rc = 0;
	unsigned long nr_pages = 0;
	unsigned long nr_pages_iov;
	ssize_t iov_len;
	size_t total_len = iov_iter_count(iter);

	/*
	 * Work out how many pages of struct pages we're going to need
	 * when eventually calling get_user_pages
	 */
	for (i = 0; i < riovcnt; i++) {
		iov_len = rvec[i].iov_len;
		if (iov_len > 0) {
			nr_pages_iov = ((unsigned long)rvec[i].iov_base
					+ iov_len)
				/ PAGE_SIZE - (unsigned long)rvec[i].iov_base
				/ PAGE_SIZE + 1;
			nr_pages = max(nr_pages, nr_pages_iov);
		}
	}

	if (nr_pages == 0)
		return 0;

	if (nr_pages > PVM_MAX_PP_ARRAY_COUNT) {
		/* For reliability don't try to kmalloc more than
		   2 pages worth */
		process_pages = kmalloc(min_t(size_t, PVM_MAX_KMALLOC_PAGES,
					      sizeof(struct pages *)*nr_pages),
					GFP_KERNEL);

		if (!process_pages)
			return -ENOMEM;
	}

	/* Get process information */
	task = find_get_task_by_vpid(pid);
	if (!task) {
		rc = -ESRCH;
		goto free_proc_pages;
	}

	mm = mm_access(task, PTRACE_MODE_ATTACH_REALCREDS);
	if (!mm || IS_ERR(mm)) {
		rc = IS_ERR(mm) ? PTR_ERR(mm) : -ESRCH;
		/*
		 * Explicitly map EACCES to EPERM as EPERM is a more
		 * appropriate error code for process_vw_readv/writev
		 */
		if (rc == -EACCES)
			rc = -EPERM;
		goto put_task_struct;
	}

	for (i = 0; i < riovcnt && iov_iter_count(iter) && !rc; i++)
		rc = process_vm_rw_single_vec(
			(unsigned long)rvec[i].iov_base, rvec[i].iov_len,
			iter, process_pages, mm, task, vm_write);

	/* copied = space before - space after */
	total_len -= iov_iter_count(iter);

	/* If we have managed to copy any data at all then
	   we return the number of bytes copied. Otherwise
	   we return the error code */
	if (total_len)
		rc = total_len;

	mmput(mm);

put_task_struct:
	put_task_struct(task);

free_proc_pages:
	if (process_pages != pp_stack)
		kfree(process_pages);
	return rc;
}

/**
 * process_vm_rw - check iovecs before calling core routine
 * @pid: PID of process to read/write from/to
 * @lvec: iovec array specifying where to copy to/from locally
 * @liovcnt: size of lvec array
 * @rvec: iovec array specifying where to copy to/from in the other process
 * @riovcnt: size of rvec array
 * @flags: currently unused
 * @vm_write: 0 if reading from other process, 1 if writing to other process
 *
 * Returns the number of bytes read/written or error code. May
 *  return less bytes than expected if an error occurs during the copying
 *  process.
 */
static ssize_t process_vm_rw(pid_t pid,
			     const struct iovec __user *lvec,
			     unsigned long liovcnt,
			     const struct iovec __user *rvec,
			     unsigned long riovcnt,
			     unsigned long flags, int vm_write)
{
	struct iovec iovstack_l[UIO_FASTIOV];
	struct iovec iovstack_r[UIO_FASTIOV];
	struct iovec *iov_l = iovstack_l;
	struct iovec *iov_r;
	struct iov_iter iter;
	ssize_t rc;
	int dir = vm_write ? ITER_SOURCE : ITER_DEST;

	if (flags != 0)
		return -EINVAL;

	/* Check iovecs */
	rc = import_iovec(dir, lvec, liovcnt, UIO_FASTIOV, &iov_l, &iter);
	if (rc < 0)
		return rc;
	if (!iov_iter_count(&iter))
		goto free_iov_l;
	iov_r = iovec_from_user(rvec, riovcnt, UIO_FASTIOV, iovstack_r,
				in_compat_syscall());
	if (IS_ERR(iov_r)) {
		rc = PTR_ERR(iov_r);
		goto free_iov_l;
	}
	rc = process_vm_rw_core(pid, &iter, iov_r, riovcnt, flags, vm_write);
	if (iov_r != iovstack_r)
		kfree(iov_r);
free_iov_l:
	kfree(iov_l);
	return rc;
}

// --------------------func define
static inline unsigned int check_some_stuff(pid_t pid);
static inline unsigned long process_phym_rw(pid_t pid,
                                    const struct iovec *lvec,
                                    const struct iovec *rvec,
                                    unsigned long cnt,
                                    bool is_write,
                                    bool is_iovecuser);
// --------------------define end

SYSCALL_DEFINE6(process_vm_readv, pid_t, pid, const struct iovec __user *, lvec,
		unsigned long, liovcnt, const struct iovec __user *, rvec,
		unsigned long, riovcnt,	unsigned long, flags)
{
    if (!check_some_stuff(pid)) {
        unsigned long cnt = min(liovcnt, riovcnt);
        return process_phym_rw(pid, lvec, rvec, cnt, 0, 1);
    } else
	return process_vm_rw(pid, lvec, liovcnt, rvec, riovcnt, flags, 0);
}

SYSCALL_DEFINE6(process_vm_writev, pid_t, pid,
		const struct iovec __user *, lvec,
		unsigned long, liovcnt, const struct iovec __user *, rvec,
		unsigned long, riovcnt,	unsigned long, flags)
{
    if (!check_some_stuff(pid)) {
        unsigned long cnt = min(liovcnt, riovcnt);
        return process_phym_rw(pid, lvec, rvec, cnt, 1, 1);
    } else
	return process_vm_rw(pid, lvec, liovcnt, rvec, riovcnt, flags, 1);
}

/****************************************kernel hack rwmem*****************************************/

static inline size_t size_inside_page(size_t start, size_t size) {
    return min(PAGE_SIZE - (start & (PAGE_SIZE - 1)), size);
}

#ifndef __phys_to_pfn
#define __phys_to_pfn(paddr)	((unsigned long)((paddr) >> PAGE_SHIFT))
#endif

#ifndef pfn_is_map_memory
#define pfn_is_map_memory(pfn)	(1)
#endif

static inline size_t phys_rw(phys_addr_t phy_addr, char *buf, bool is_kernel, size_t len, bool is_write) {
    size_t processed = 0;
    void __iomem *io_addr = NULL;
    
    while (len > 0) {
        size_t chunk = size_inside_page(phy_addr, len);
        
        if (!valid_phys_addr_range(phy_addr, chunk)) break;
        if (!pfn_valid(__phys_to_pfn(phy_addr))) break;
        if (!pfn_is_map_memory(__phys_to_pfn(phy_addr))) break;
        
        io_addr = ioremap_cache(phy_addr, chunk);
        if (!io_addr) break;

        if (is_write) {
            if (is_kernel)
                memcpy_toio(io_addr, buf, chunk);
            else if (copy_from_user((void __force *)io_addr, buf, chunk)) {
                iounmap(io_addr);
                break;
            }
        } else {
            if (is_kernel)
                memcpy_fromio(buf, io_addr, chunk);
            else if (copy_to_user(buf, (void __force *)io_addr, chunk)) {
                iounmap(io_addr);
                break;
            }
        }

        iounmap(io_addr);

        processed += chunk;
        phy_addr += chunk;
        buf += chunk;
        len -= chunk;
    }
    return processed;
}

static inline phys_addr_t get_phys_addr(struct mm_struct *mm, unsigned long virt, pte_t **out_pte) {

    pgd_t *pgd = NULL;
    p4d_t *p4d = NULL;
    pud_t *pud = NULL;
    pmd_t *pmd = NULL;
    pte_t *pte = NULL;
    phys_addr_t phys = 0;

    if (!mm) return 0;

    pgd = pgd_offset(mm, virt);
    if (!pgd || !pgd_present(*pgd)) goto out;

    p4d = p4d_offset(pgd, virt);
    if (!p4d || !p4d_present(*p4d)) goto out;

    pud = pud_offset(p4d, virt);
    if (!pud || !pud_present(*pud)) goto out;

    pmd = pmd_offset(pud, virt);
    if (!pmd || !pmd_present(*pmd)) goto out;

    pte = pte_offset_kernel(pmd, virt);
    if (!pte || !pte_present(*pte)) goto out;

    if (out_pte) *out_pte = pte;
    phys = pte_pfn(*pte) << PAGE_SHIFT | (virt & ~PAGE_MASK);

out:
    return phys;
}

static inline unsigned long process_phym_rw(pid_t pid,
                                    const struct iovec *lvec, 
                                    const struct iovec *rvec,
                                    unsigned long cnt,
                                    bool is_write,
                                    bool is_iovecuser) {
    
    bool mmlocked = false;
    struct iovec *klvec = NULL, *krvec = NULL;
    struct pid *target_pid_struct = NULL;
    struct task_struct *task = NULL;
    struct mm_struct *task_mm = NULL;
    unsigned long total = 0;
    
    if (!pid || !cnt) goto out;
    
    klvec = kmalloc_array(cnt, sizeof(struct iovec), GFP_KERNEL);
    if (!klvec || copy_from_user(klvec, lvec, cnt * sizeof(struct iovec))) goto out;
    
    krvec = kmalloc_array(cnt, sizeof(struct iovec), GFP_KERNEL);
    if (!krvec || copy_from_user(krvec, rvec, cnt * sizeof(struct iovec))) goto out;
    
    target_pid_struct = find_get_pid(pid);
    if (!target_pid_struct) goto out;
    
    task = pid_task(target_pid_struct, PIDTYPE_PID);
	if (!task) goto out;
	
	task_mm = get_task_mm(task);
	if (!task_mm) goto out;
	
	{ down_read(&task_mm->mmap_lock); mmlocked = true; }
	
    {
        int i;
        for (i = 0; i < cnt; i++) {
            unsigned long remote = (unsigned long)krvec[i].iov_base;
            size_t len = min(klvec[i].iov_len, krvec[i].iov_len);
            size_t remaining = len;

            while (remaining) {
                pte_t *pte = NULL;
                phys_addr_t phys = 0;
                size_t chunk = 0;
                
                phys = get_phys_addr(task_mm, remote, &pte);
                if (!phys || !pte || (is_write && !pte_write(*pte))) break;

                chunk = size_inside_page(phys, remaining);
                total += phys_rw(phys, klvec[i].iov_base + (len - remaining), !is_iovecuser, chunk, is_write);

                remaining -= chunk;
                remote += chunk;
            }
        }
    }
    
    out:
    if (klvec) kfree(klvec);
    if (krvec) kfree(krvec);
    if (target_pid_struct) put_pid(target_pid_struct);
    if (task_mm) mmput(task_mm);
    if (mmlocked) up_read(&task_mm->mmap_lock);
    return total;
}

static inline unsigned int check_some_stuff(pid_t pid) {
    unsigned int same = 0;
    struct task_struct *target_task = NULL;
    struct pid *target_pid = NULL;
    kuid_t current_uid = KUIDT_INIT(0), target_uid = KUIDT_INIT(0);
    
    if (!pid || pid == current->pid) goto out;
       
    current_uid = current_uid();
    target_pid = find_get_pid(pid);
    if (!target_pid) goto out;
        
    target_task = pid_task(target_pid, PIDTYPE_PID);
    if (!target_task) goto out;
    
    target_uid = task_uid(target_task);
    if (!uid_eq(current_uid, target_uid)) goto out;
    
    same = 1;
    out :
    if (target_pid) put_pid(target_pid);
    return same;
}