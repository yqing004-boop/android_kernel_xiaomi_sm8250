#!/usr/bin/env python3
"""Checked compatibility edits for the pinned SukiSU v4.3.0-r2 on a 4.19 kernel.

Targets:
- optional file_operations members (iopoll/remap_file_range) with nested guards
- absent seccomp action cache (no cache layout assumptions)
- <uapi/linux/mount.h> which does not exist on 4.19
- path_mount() which does not exist before 5.9 (backport via do_mount)
- <linux/minmax.h> which does not exist on 4.19 (min/min_t live in kernel.h)
"""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
ksu = root / 'KernelSU/kernel'


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise SystemExit('Compatibility anchor mismatch: ' + old[:120])
    return text.replace(old, new, 1)


def guard_block(text, start, end, condition):
    begin = text.index(start)
    finish = text.index(end, begin)
    return (text[:begin] + '#if ' + condition + '\n' + text[begin:finish]
            + '#endif\n\n' + text[finish:])


# --- file_wrapper.c: optional iopoll/remap_file_range -------------------------
fw = ksu / 'infra/file_wrapper.c'
s = fw.read_text()
s = guard_block(s,
    '#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)\nstatic int ksu_wrapper_iopoll',
    '#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)\nstatic int ksu_wrapper_iterate',
    'defined(KSU_COMPAT_HAS_IOPOLL)')
s = guard_block(s, 'static loff_t ksu_wrapper_remap_file_range',
    'static int ksu_wrapper_fadvise', 'defined(KSU_COMPAT_HAS_REMAP)')
for member, macro in [('iopoll', 'KSU_COMPAT_HAS_IOPOLL'),
                      ('remap_file_range', 'KSU_COMPAT_HAS_REMAP')]:
    line = next(line for line in s.splitlines() if 'p->ops.' + member + ' =' in line)
    s = replace_once(s, line, '#ifdef ' + macro + '\n' + line + '\n#endif')
fs_h = (root / 'include/linux/fs.h').read_text()
prefix = ''
if '(*iopoll)' in fs_h:
    prefix += '#define KSU_COMPAT_HAS_IOPOLL 1\n'
if '(*remap_file_range)' in fs_h:
    prefix += '#define KSU_COMPAT_HAS_REMAP 1\n'
fw.write_text(prefix + s)

# --- seccomp_cache.c: no action cache on 4.19 --------------------------------
cache = ksu / 'infra/seccomp_cache.c'
s = cache.read_text()
has_cache = 'struct action_cache' in (root / 'kernel/seccomp.c').read_text()
s = replace_once(s, 'struct action_cache {',
    '#if defined(KSU_COMPAT_HAS_SECCOMP_CACHE) && defined(SECCOMP_ARCH_NATIVE_NR)\nstruct action_cache {')
s += '''
#else
/* No cache exists to invalidate or populate on this kernel. */
void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
    (void)filter;
    (void)nr;
}
void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
    (void)filter;
    (void)nr;
}
#endif
'''
if has_cache:
    raise SystemExit('Unexpected seccomp cache backport: review exact filter layout first')
cache.write_text(s)

# --- su_mount_ns.c: uapi/linux/mount.h + path_mount --------------------------
sn = ksu / 'infra/su_mount_ns.c'
s = sn.read_text()
s = replace_once(s, '#include <uapi/linux/mount.h>\n', '')
s = replace_once(s,
    'extern int path_mount(const char *dev_name, struct path *path, const char *type_page, unsigned long flags,\n'
    '                      void *data_page);',
    '''#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
extern int path_mount(const char *dev_name, struct path *path, const char *type_page, unsigned long flags,
                      void *data_page);
#else
#include <asm/uaccess.h>
static int path_mount(const char *dev_name, struct path *path, const char *type_page, unsigned long flags,
                      void *data_page)
{
    char *buf;
    char *dir;
    int ret;
    mm_segment_t old_fs;

    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    dir = d_path(path, buf, PATH_MAX);
    if (IS_ERR(dir)) {
        ret = PTR_ERR(dir);
        kfree(buf);
        return ret;
    }

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = do_mount(dev_name, (const char __user *)dir, type_page, flags, data_page);
    set_fs(old_fs);

    kfree(buf);
    return ret;
}
#endif''')
sn.write_text(s)

# --- sulog/event.c: linux/minmax.h -> linux/kernel.h -------------------------
ev = ksu / 'sulog/event.c'
s = ev.read_text()
s = replace_once(s, '#include <linux/minmax.h>\n', '#include <linux/kernel.h>\n')
ev.write_text(s)

# --- pkg_observer.c: fsnotify handle_inode_event 是 5.9+ API，4.19 用 handle_event ---
# 动态管理器监听在 4.19 上禁用（不影响预置签名管理器和 root）。
po = ksu / 'manager/pkg_observer.c'
s = po.read_text()
if 'KERNEL_VERSION(5, 9, 0)' not in s:
    s = '#include <linux/version.h>\n#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)\n' + s
    s += '\n#else\nint ksu_observer_init(void) { return 0; }\nvoid ksu_observer_exit(void) {}\n#endif\n'
    po.write_text(s)

print('SukiSU 4.19 compatibility: headers + path_mount + optional ops + seccomp cache + pkg_observer handled')
