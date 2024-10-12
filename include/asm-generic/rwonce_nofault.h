/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __ASM_GENERIC_RWONCE_NOFAULT_H
#define __ASM_GENERIC_RWONCE_NOFAULT_H

#define __READ_ONCE_NOFAULT(p, _label) ({ goto _label; })

#define READ_ONCE_NOFAULT(x, _label) ({ goto _label; })

#define __WRITE_ONCE_NOFAULT(p, v, _label) ({ goto _label; })

#define WRITE_ONCE_NOFAULT(p, v, _label) ({ goto _label; })

#endif /* __ASM_GENERIC_RWONCE_NOFAULT_H */
