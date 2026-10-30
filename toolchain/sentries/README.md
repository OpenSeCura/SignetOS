# sentries: call sentries and local return sentries

A local, **not ratified** extension that splits CHERI sentries into two kinds:

- **call sentries**, which only the holder of a type 1 authority makes, with
  `yseal`;
- **return sentries**, which only the hardware makes, as the link a jump writes.

Only a return can use a return sentry, a return can use nothing else, and a
return sentry is local, so it can only be kept on a stack. `patches/` adds the
extension to QEMU. LLVM needs no change: compiled code already calls with a
link into `cra` and returns with `ret`, and `yseal` is Zyseal's.

```
setup.sh     applies the patches to the QEMU tree (run by ../setup.sh)
patches/     01-qemu-sentries (7 files): return sentries
             02-qemu-sentry-authority (2 files): call sentries need an authority
```

`../setup.sh` runs `./setup.sh` after the Zyseal and mmodemmu patches and
before it builds QEMU. It needs Zyseal's capability format: the new types sit
in the CT 2..7 block that Zyseal's 5-bit CT keeps for sentry types. A patch
that is already applied is skipped.

## The extension

- **Enabling it:** `-cpu rv64,...,Zylevels1=on,sentries=on`. It is off by
  default.
- **Needs `Zylevels1`:** return sentries are local, which means nothing without
  capability levels. QEMU refuses to start with `sentries=on` alone.
- **Without it:** a link is a CT 1 sentry, `sentry` makes CT 1 and `yseal`
  refuses type 1, as in stock RVY and Zyseal.

### Types

Three kinds of `cjalr`: a **return** is `jalr x0, 0(ra)` (`ret`); a **call**
links (`rd` is not `x0`); a **jump** is any other (a tail call, `jr ct0`).

| CT | name | made by | call | jump | return |
|---|---|---|---|---|---|
| 0 | unsealed | | allowed | allowed | seal fault |
| 1 | call sentry | `yseal` under a type 1 authority | allowed | allowed | seal fault |
| 2 | return sentry | link of `cjal`/`cjalr` | seal fault | seal fault | allowed |
| 3–7 | reserved | nothing | seal fault | seal fault | seal fault |

Anything local other than a return sentry can't be called or jumped to
either: a CHERI permission violation (cause: global).

A jump to any sentry needs offset 0 and unseals it on arrival, as for stock
sentries. A fault is a CHERI seal violation, reported against the source
register.

### Call sentries

- **Only an authority makes them.** `yseal` makes CT 1 when its authority
  names type 1 (address 1, SE). The `sentry` instruction gives its input back
  untagged, and `cbld` rebuilds no call sentry, as it rebuilds no return
  sentry. On SignetOS the kernel holds the only type 1 authority
  (`sealing::g_sentry_auth`), so every call sentry is one it made.
- **Its holder is trusted.** Nothing else is checked: whoever holds the
  authority answers for what it seals. With an ambient `sentry`, anyone could
  seal something that faults whoever jumps through it (no X, an odd address)
  and hand it out as an entry point.
- **Opened only by the jump.** `yunseal` still refuses every CT below 8.

### Return sentries

- **Only the hardware makes them.** `yseal` makes no type below 8 but, under
  an authority, type 1; `sentry` makes nothing; and `cbld` does not rebuild
  them. A capability of type 2 is therefore always a genuine link.
- **Only a return, and a return only through one.** `ret` faults on anything
  but a return sentry, unsealed code included, and a call or jump faults on a
  return sentry. Code that links into another register and returns through
  it (the machine outliner's `jal t0` ... `jr t0`) therefore faults; none of
  SignetOS's code does that.
- **Local.** The link has GL clear. Under `Zylevels1`, storing a local
  capability through an authority without SL clears its tag. Only memory
  reached through an SL capability can hold a return sentry: on SignetOS, a
  thread stack or a kernel stack.
- **The caller gets its PCC back as it was.** The link is the caller's own PCC
  made local, and a return makes it the PCC again. Arriving through it as-is
  would leave the caller running from a local PCC after every call, and
  everything it then derived from PCC (`auipcc`) would be local too. So
  arriving sets GL again.
- **Code never runs local, which makes that exact.** A call or jump to a local
  capability faults (unless it is a return through a return sentry), so every
  link was made by global code. The one way left to run local, an exception
  return to a local `xepcc`, gets an untagged link from any call it makes, so
  it can never come back global.
- **Why there is no return-to-local kind.** Local code would only be useful
  for a sentry handed to someone else for the length of one call, so they
  could not keep it. On SignetOS code never crosses between compartments
  (entry points do), and within one compartment there is nothing to protect.
- **Loads.** A load through a local authority without EL clears GL on the
  loaded capability, sealed or not. On a return sentry it is already clear,
  so nothing changes.
- **Exception return.** `sret` and `mret` accept a return sentry in
  `sepcc`/`mepcc` as they accept a CT 1 sentry: if the address matches, it is
  unsealed and made global again. They are not returns in the sense above,
  so they also still accept anything else.

### What it does not do

- **No interrupt state.** Unlike CHERIoT's sentry types 2–5, no sentry here
  changes the interrupt enable.
