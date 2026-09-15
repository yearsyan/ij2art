// teardown_stub.S -- the trampoline and entry shim that tear the carrier down entirely
// when a non-target child process is specialized.
//
// Two pieces work together:
//  1) __ij2art_hook_shim (the real target installed in the GOT): its first instruction
//     pushes all callee-saved registers (x19-x28) and fp/lr into a 128-byte context block
//     on the stack, records the block's address in g_entry_save, and then tail-jumps to the
//     C implementation. The shape of the compiler prologue (the fp+16 produced by sub+stp
//     differs from the entry sp) and the way the C implementation uses x19-x28 no longer
//     affect the correctness of the saved context.
//  2) __ij2art_teardown_start (copied into a dedicated RX page and executed there; it never
//     returns): calls __loader_dlclose(self_handle) to deregister the solist and _r_debug
//     chains, unmap the segments and free the soinfo -- this clears the linker-side
//     registrations that a bare munmap would leave behind; it then fully rebuilds
//     x19-x28/x29/x30/sp from the context block and tail-jumps to the original
//     selinux_android_setcontext with the original arguments. All the intervening carrier
//     stack frames (including those above the context block) become dead memory and are then
//     overwritten naturally.
//
// desc (inside the page, still mapped after dlclose): { orig, dlclose, handle, save, a0..a3 }
    .section .rodata.teardown_stub, "a"
    .p2align 2
    .global __ij2art_teardown_start
    .type __ij2art_teardown_start, %object
__ij2art_teardown_start:
    bti  c                      // NOP when the page is not marked PROT_BTI; correct when it is
    ldr  x0,  [x4, #16]         // handle
    ldr  x19, [x4, #8]          // __loader_dlclose -- the x19/x22/x23 uses below
    ldr  x22, [x4, #24]         // context block base    are only borrows: the real values
    mov  x23, x4                // desc (separate page)  live in the block, which dlclose
    blr  x19                    // preserves; dlclose(handle) clobbers all of x0-x18
    ldr  x8,  [x23, #0]         // original setcontext
    ldr  x0,  [x23, #32]        // the original four args
    ldr  x1,  [x23, #40]
    ldr  x2,  [x23, #48]
    ldr  x3,  [x23, #56]
    add  sp, x22, #128          // original sp; the context block occupies [sp-128, sp)
    ldp  x29, x30, [sp, #-128]
    ldp  x27, x28, [sp, #-112]
    ldp  x25, x26, [sp, #-96]
    ldp  x23, x24, [sp, #-80]
    ldr  x21, [sp, #-64]
    ldr  x22, [sp, #-56]
    ldp  x19, x20, [sp, #-48]
    br   x8                     // setcontext returns to the original ra; flow continues seamlessly
    .global __ij2art_teardown_end
__ij2art_teardown_end:
    .size __ij2art_teardown_start, . - __ij2art_teardown_start

    .text
    .p2align 2
    .global __ij2art_hook_shim
    .type __ij2art_hook_shim, %function
// context block layout: +0 x29, +8 x30, +16 x27/x28, +32 x25/x26, +48 x23/x24,
//             +64 x21/x22, +80 x19/x20; x0..x3 are handed to the C implementation
//             exactly as received.
__ij2art_hook_shim:
    bti  c
    stp  x29, x30, [sp, #-128]!
    stp  x27, x28, [sp, #16]
    stp  x25, x26, [sp, #32]
    stp  x23, x24, [sp, #48]
    stp  x21, x22, [sp, #64]
    stp  x19, x20, [sp, #80]
    adrp x9, g_entry_save
    mov  x11, sp                // sp cannot be stored directly, so go through a register
    str  x11, [x9, :lo12:g_entry_save]
    bl   hook_setcontext_impl   // normal path (target App/fallback): x19-x28 are preserved
                                // by the C ABI, and x0 holds the setcontext return code
    ldr  x30, [sp, #8]          // restore the original ra
    add  sp, sp, #128           // pop the context block, restoring sp to the caller's expectation
    ret
    .size __ij2art_hook_shim, . - __ij2art_hook_shim
