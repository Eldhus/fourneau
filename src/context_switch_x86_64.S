# fourneau_context_switch(s: *const std.Io.fiber.Switch) callconv(.c)
#     *const std.Io.fiber.Switch
#
# std.Io.fiber.contextSwitch's contract, as an ordinary function: save the
# current context into s.old, resume s.new, and hand the resumed side the
# message pointer: in rsi (where a new fiber's entry stub looks for it)
# and as this function's return value (where a context resumed from a
# switch looks for it). Switch is { old: *Context, new: *Context }, and
# Context is { rsp, rbp, rip }.
#
# Why our own: Zig 0.17's ReleaseSafe build miscompiles std's inline
# assembly version (the message pointer is never loaded into rsi), so both
# our vendored Io.Evented and the simulator crashed in -O safe, which is
# how production runs (DIARY 2026-10-05). As a real call it needs no
# operand constraints: the C calling convention says which registers the
# caller saves, and this saves the rest (rbx, r12-r15, the MXCSR and x87
# control words on the stack; rsp, rbp, rip in the context).

    .text
    .globl fourneau_context_switch
    .type fourneau_context_switch, @function
fourneau_context_switch:
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $8, %rsp
    stmxcsr (%rsp)
    fnstcw 4(%rsp)
    movq 0(%rdi), %rax          # s.old
    movq 8(%rdi), %rcx          # s.new
    leaq 1f(%rip), %rdx
    movq %rsp, 0(%rax)
    movq %rbp, 8(%rax)
    movq %rdx, 16(%rax)
    movq 0(%rcx), %rsp
    movq 8(%rcx), %rbp
    movq %rdi, %rsi             # the message, for whoever resumes
    jmpq *16(%rcx)
1:
    # Resumed by another switch: rsi holds the message it sent.
    ldmxcsr (%rsp)
    fldcw 4(%rsp)
    addq $8, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    movq %rsi, %rax
    ret
    .size fourneau_context_switch, . - fourneau_context_switch

    .section .note.GNU-stack, "", @progbits
