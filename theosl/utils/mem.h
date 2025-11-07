#ifndef _THSOSL_UTILS_MEM_H
#define _THSOSL_UTILS_MEM_H

#ifdef __x86_64__

#define THEOSL_HUGEPAGE_SIZE (1ULL << 21) 
#define THESL_HUGEPAGE_MMAP_FLAGS (MAP_HUGETLB | MAP_HUGE_2MB)

#define THEOSL_MEGAPAGE_SIZE (1ULL << 30)
#define THSOSL_MEGAPAGE_MMAP_FLAGS (MAP_HUGETLB | MAP_HUGE_1GB)
#else
  #error non x86_64 targets are not supported
  // for aarch64 there are many hugepage sizes so it's non trivial to do and I do not have aarch64 so I don't want to deal with it
#endif


#endif
