.text
.macro FUNC name
.p2align 2
.global reloc_\name
.type reloc_\name, %function
reloc_\name:
.endm
.macro END name
.size reloc_\name, .-reloc_\name
.endm

FUNC adr
    adr x0, .Ladr_data
    ldr x0, [x0]
    ret
END adr
.p2align 3
.Ladr_data: .xword 37

FUNC adrp
    adrp x9, .Ladrp_data
    ldr x0, [x9, :lo12:.Ladrp_data]
    ret
END adrp

FUNC literal
    ldr x0, .Lliteral_data
    ret
END literal
.p2align 3
.Lliteral_data: .xword 41

FUNC branch
    b .Lbranch_body
    nop
.Lbranch_body:
    add x0, x0, #43
    ret
END branch

FUNC cbz
    cbz x0, .Lzero
    add x0, x0, #47
    ret
.Lzero:
    mov x0, #53
    ret
END cbz

FUNC pac
    hint #25 // paciasp
    add x0, x0, #59
    hint #29 // autiasp
    ret
END pac

.section .rodata
.p2align 3
.Ladrp_data: .xword 39
.section .note.GNU-stack,"",%progbits
