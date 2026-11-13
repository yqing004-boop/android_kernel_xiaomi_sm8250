#!/usr/bin/env python3
"""Apply checked compatibility edits to the pinned SukiSU v4.3.0-r2."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
ksu = root / 'KernelSU/kernel'


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise SystemExit('Compatibility anchor mismatch: ' + old[:100])
    return text.replace(old, new, 1)


def guard_block(text, start, end, condition):
    begin = text.index(start)
    finish = text.index(end, begin)
    return (text[:begin] + '#if ' + condition + '\n' + text[begin:finish]
            + '#endif\n\n' + text[finish:])


fw = ksu / 'infra/file_wrapper.c'
s = fw.read_text()
# Wrap BOTH branches, preserving the upstream 6.1 signature selection.
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

cache = ksu / 'infra/seccomp_cache.c'
s = cache.read_text()
# This kernel has no action cache. Never cast its filter to a newer layout.
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
print('SukiSU 4.19 compatibility: optional file operations guarded; absent seccomp cache untouched')
