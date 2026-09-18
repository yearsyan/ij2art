.text
.p2align 2
.global probe_target
.type probe_target, %function
probe_target:
    mov x16, #0x1616
    mov x17, #0x1717
    add x9, x0, #7
    cmp x0, x1
    // Observe +0x10: live GPRs and condition flags must survive the callback.
    eor x9, x9, x1
    csel x0, x9, x1, ge
    ret
.size probe_target, .-probe_target

.p2align 2
.global probe_simd
.type probe_simd, %function
probe_simd:
    fmov d0, #1.0
    fmov d1, #2.0
    // Observe +0x8: caller-saved SIMD registers are live at this instruction.
    fadd d0, d0, d1
    fmov x0, d0
    ret
.size probe_simd, .-probe_simd
.section .note.GNU-stack,"",%progbits
