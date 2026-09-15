#include "jni_abi_constants.h"

// All instructions are assembled at build time. No writable code, mmap(PROT_EXEC),
// per-signature code generation or ART quick-frame emulation is involved here.
.text
.p2align 2
.altmacro
.macro E4_SLOT number
.global ij2art_jni_slot_\number
.hidden ij2art_jni_slot_\number
.type ij2art_jni_slot_\number, %function
ij2art_jni_slot_\number:
    hint #34                       // bti c: THIS is the indirect call destination.
    mov x9, #\number
    b ij2art_jni_common
.size ij2art_jni_slot_\number, .-ij2art_jni_slot_\number
.endm
.set slot_number, 0
.rept IJ2ART_JNI_SLOTS
E4_SLOT %slot_number
.set slot_number, slot_number + 1
.endr

.type ij2art_jni_common, %function
ij2art_jni_common:
.cfi_startproc
    hint #25                       // paciasp (NOP on CPUs without PAC).
.cfi_negate_ra_state
    stp x29, x30, [sp, #-IJ2ART_JNI_FRAME_SIZE]!
.cfi_def_cfa_offset IJ2ART_JNI_FRAME_SIZE
.cfi_offset x29, -IJ2ART_JNI_FRAME_SIZE
.cfi_offset x30, -(IJ2ART_JNI_FRAME_SIZE-8)
    mov x29, sp
    stp x0, x1, [sp, #16]
    stp x2, x3, [sp, #32]
    stp x4, x5, [sp, #48]
    stp x6, x7, [sp, #64]
    stp d0, d1, [sp, #80]
    stp d2, d3, [sp, #96]
    stp d4, d5, [sp, #112]
    stp d6, d7, [sp, #128]
    mov x0, x9
    add x1, sp, #IJ2ART_JNI_CAPTURE_OFFSET
    add x2, sp, #IJ2ART_JNI_FRAME_SIZE // caller's SP, NOT the new frame pointer.
    bl ij2art_jni_dispatch
    cmp x1, #1
    b.eq .Lfloat
    cmp x1, #2
    b.ne .Ldone                     // integers, references and void use x0.
    fmov d0, x0
    b .Ldone
.Lfloat:
    fmov s0, w0
.Ldone:
    ldp x29, x30, [sp], #IJ2ART_JNI_FRAME_SIZE
.cfi_restore x29
.cfi_restore x30
.cfi_def_cfa_offset 0
    hint #29                       // autiasp with the original SP.
.cfi_negate_ra_state
    ret
.cfi_endproc
.size ij2art_jni_common, .-ij2art_jni_common

.section .data.rel.ro, "aw", %progbits
.p2align 3
.global ij2art_jni_slots
.hidden ij2art_jni_slots
.type ij2art_jni_slots, %object
ij2art_jni_slots:
.macro E4_ADDRESS number
    .xword ij2art_jni_slot_\number
.endm
.set slot_number, 0
.rept IJ2ART_JNI_SLOTS
E4_ADDRESS %slot_number
.set slot_number, slot_number + 1
.endr
.size ij2art_jni_slots, .-ij2art_jni_slots
.section .note.GNU-stack,"",%progbits
