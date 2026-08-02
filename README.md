# SafeMod

sukisu presence detector.

## usage

install the module zip from releases.

at boot the service runs a userspace scan and writes audit.log in the
module dir. module description shows [user:xxx].

the action button installs the lkm matching your kernel version, reads
/proc/safemod, unloads it, appends the result to audit.log. description
becomes [user:xxx,Ker:xxx].

the lkm is never auto installed.

## audit

audit.log at /data/adb/modules/safemod/audit.log. cleared every boot,
userspace result written fresh, lkm results appended by the button.

Thanks to [阿尔托莉雅·潘德拉贡](https://www.coolapk.com/u/41654149) for providing
the device for GKI 6.1 testing.

## license

GPL-2.0
