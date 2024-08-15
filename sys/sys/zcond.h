#ifdef _KERNEL
#ifndef _SYS_ZCOND_H
#define _SYS_ZCOND_H

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>

#include <machine/zcond.h>

/*
 * The zcond interface provides a low-cost mechanism for conditional execution.
 * It is applicable in situations where branch selection is performed by
 * inspecting the state of a single boolean flag i.e blocks of the following
 * form: if(flag) {
 *      // do something
 *  }
 *
 * This kind of block is compiled into some sequence of load, test, jump
 * assembly instructions. The low cost provided by zcond is achieved by "baking
 * in" a single branch direction at compile time. This means outputting either
 * an unconditional jump or a nop, while the memory access is avoided.
 *
 * When the time comes to switch the branch direction, the current instruction
 * (jump or nop) is patched at runtime to a corresponding instruction (nop or
 * jump). Keep in mind that this is an expensive operation, since all cpus
 * except the one performing the patch need to be halted.
 *
 *
 * To use a zcond, first define it with: ZCOND_DEFINE_TRUE(name) or
 * ZCOND_DEFINE_FALSE(name) Alternatively, declare it with
 * ZCOND_DECLARE_TRUE(name) or ZCOND_DECLARE_FALSE(name). Then initialize it
 * with ZCOND_INIT(true) or ZCOND_INIT(false).
 *
 * Use zcond_false(cond) or zcond_true(cond) to inspect the state of a zcond.
 *
 * To flip the state of a zcond, use zcond_enable(cond) and zcond_disable(cond).
 * Zconds are reference counted, so zcond_enable() increments the reference
 * count while zcond_disable() decrements it.
 *
 * This header includes the interface intended to be used by consumers, as well
 * as some MI code. MD support can be found in sys/<arch>/include/zcond.h and
 * sys/<arch>/<arch>/zcond_machdep.c
 */

/*
 * Describes a single inspection of the zcond state (performed with an if
 * statement). Holds all the data neccessary to perform a safe instruction
 * patch.
 */
struct patch_point {
	vm_offset_t patch_addr; /* address of the nop or jmp instruction to be
				   patched */
	vm_offset_t lbl_true_addr; /* address of the label to jump to when the
				      condition is true */
	struct zcond *
	    zcond; /* pointer to the zcond inspected by this inspection point */
	SLIST_ENTRY(patch_point) next;
} __attribute__((packed));

/*
 * A single optimized boolean.
 */
struct zcond {
	bool enabled;
	int refcnt;
	SLIST_HEAD(, patch_point) patch_points;
};

/*
 * Wrapper types are needed for compile time decision making.
 */
struct zcond_true {
	struct zcond cond;
};

struct zcond_false {
	struct zcond cond;
};

#define ZCOND_ELF_SECTION "set_zcond_patch_points_set"
#define ZCOND_LINKER_SET  zcond_patch_points_set

/*
 * __zcond_table is an ELF section which keeps
 * all the data related to the zcond mechanism.
 * A single entry describes a single patch_point.
 */
#define ZCOND_TABLE_ENTRY                                 \
	".pushsection " ZCOND_ELF_SECTION ", \"aw\" \n\t" \
	".quad 1b \n\t"                                   \
	".quad %l[l_true] \n\t"                           \
	".quad %c0 \n\t"                                  \
	".quad 0 \n\t"                                    \
	".popsection \n\t"

#define ZCOND_SET_START_STOP do {                              \
	__WEAK(__CONCAT(__start_set_, ZCOND_LINKER_SET)); \
	__WEAK(__CONCAT(__stop_set_, ZCOND_LINKER_SET)); \
    }while(0);

/*
 * Emits a __zcond_table entry, describing one patch_point.
 * Bakes in a nop instruction instruction, so the return value is initially
 * false.
 */
static __always_inline bool
zcond_nop(struct zcond *const zcond_p)
{
	ZCOND_SET_START_STOP
	asm goto("1: " ZCOND_NOP_ASM ZCOND_TABLE_ENTRY
		 :
		 : "i"(zcond_p)
		 :
		 : l_true);

	return (false);
l_true:
	return (true);
}

/*
 * Emits a __zcond_table entry, describing one patch_point.
 * Bakes in a jmp instruction instruction, so the return value is initially
 * true.
 */
static __always_inline bool
zcond_jmp(struct zcond *const zcond_p)
{
	ZCOND_SET_START_STOP
	asm goto("1:" ZCOND_JMP_ASM " %[l_true] \n\t" ZCOND_TABLE_ENTRY
		 :
		 : "i"(zcond_p)
		 :
		 : l_true);
	return (false);
l_true:
	return (true);
}

/*
 * These macros declare and initialize a new zcond.
 */

#define ZCOND_INIT(state)                                              \
	{                                                              \
		{                                                      \
			.enabled = (state), .refcnt = (state ? 1 : 0), \
			.patch_points = SLIST_HEAD_INITIALIZER()       \
		}                                                      \
	}

#define DEFINE_ZCOND_TRUE(name)	  struct zcond_true name = ZCOND_INIT(true)

#define DEFINE_ZCOND_FALSE(name)  struct zcond_false name = ZCOND_INIT(false)

#define DECLARE_ZCOND_TRUE(name)  struct zcond_true name;

#define DECLARE_ZCOND_FALSE(name) struct zcond_false name;

/*
 * These macros inspect the state of a zcond (is it true or false)
 * thus instatiating a patch_point.
 */
#define zcond_true(cond_wrapped)                                              \
	({                                                                    \
		bool branch;                                                  \
		if (__builtin_types_compatible_p(typeof(cond_wrapped),        \
			struct zcond_true)) {                                 \
			branch = zcond_jmp(&(cond_wrapped.cond));             \
		} else if (__builtin_types_compatible_p(typeof(cond_wrapped), \
			       struct zcond_false)) {                         \
			branch = zcond_nop(&(cond_wrapped.cond));             \
		}                                                             \
                                                                              \
		branch;                                                       \
	})

#define zcond_false(cond_wrapped)                                             \
	({                                                                    \
		bool branch;                                                  \
		if (__builtin_types_compatible_p(typeof(cond_wrapped),        \
			struct zcond_true)) {                                 \
			branch = zcond_nop(&(cond_wrapped.cond));             \
		} else if (__builtin_types_compatible_p(typeof(cond_wrapped), \
			       struct zcond_false)) {                         \
			branch = zcond_jmp(&(cond_wrapped.cond));             \
		}                                                             \
                                                                              \
		branch;                                                       \
	})

/*
 * These macros change the state of a zcond.
 */
#define zcond_enable(cond_wrapped) __zcond_toggle(&cond_wrapped.cond, true)
#define zcond_disable(cond_wrapped) \
	__zcond_toggle(&cond_wrapped.cond, false)

/*
 * Change the state of a zcond by safely patching all of its
 * inspection points with appropriate instructions.
 */
void __zcond_toggle(struct zcond *cond, bool enable);

/*
 * Called before a single patch_point is patched.
 */
void zcond_before_patch(void);

/*
 * Called after a single patch_point was patched.
 */
void zcond_after_patch(void);

/*
 * Forward declaration of a struct, defined separately for each architecture in
 * <machine/zcond.h>
 */
struct zcond_md_ctxt;
/*
 * Called before CPUs are parked. Use this hook to perform MD pmap loading
 * and other MD setup.
 */
void zcond_before_rendezvous(struct zcond_md_ctxt *);

/*
 * Called after the whole zcond is patched and CPUs are resumed.
 *  Use this hook to perform MD pmap cleanup.
 */
void zcond_after_rendezvous(struct zcond_md_ctxt *);

/*
 * Calculates the bytes of instruction with which the ins_p inspection point is
 * to be patched with. insn[] is populated with the instruction bytes and size
 * is set to the number of instruction bytes.
 */
void zcond_get_patch_insn(struct patch_point *ins_p, uint8_t insn[],
    size_t *size);


void 		 pmap_qenter_zcond(vm_page_t m);
void 		 pmap_qremove_zcond(void);
vm_offset_t  zcond_get_patch_va(void);

#endif
#endif
