/*
 * $FreeBSD$
 * Definitions for 3C507
 */

#define	IE507_CTRL	6	/* control port */
#define	IE507_ICTRL	10	/* interrupt control */
#define	IE507_ATTN 	11	/* any write here sends a chan attn */
#define	IE507_MADDR	14	/* shared memory configuration */
#define	IE507_IRQ	15	/* IRQ configuration */

#define	EL_CTRL_BNK1	0x01	/* register bank 1 */
#define	EL_CTRL_IEN	0x04	/* interrupt enable */
#define	EL_CTRL_INTL	0x08	/* interrupt active latch */
#define	EL_CTRL_16BIT	0x10	/* bus width; clear = 8-bit, set = 16-bit */
#define	EL_CTRL_LOOP	0x20	/* loopback mode */
#define	EL_CTRL_NRST	0x80	/* turn off to reset */
#define	EL_CTRL_RESET	(EL_CTRL_LOOP)
#define	EL_CTRL_NORMAL	(EL_CTRL_NRST | EL_CTRL_IEN | EL_CTRL_BNK1)
