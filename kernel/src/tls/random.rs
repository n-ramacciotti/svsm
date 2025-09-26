use core::arch::asm;
use getrandom::Error as GetRandomError;

/// A custom implementation of a random number generator using the `rdrand` instruction on x86_64.
/// This is a placeholder implementation.
pub fn custom_getrandom(buf: &mut [u8]) -> Result<(), GetRandomError> {
    for chunk in buf.chunks_mut(8) {
        let mut rnd: u64;
        let mut ok: u8;
        let mut tries = 0;

        loop {
            // SAFETY: `rdrand` is safe to call on x86_64 processors that support it.
            unsafe {
                asm!(
                    "rdrand {0}",
                    "setc {1}",
                    out(reg) rnd,
                    out(reg_byte) ok,
                );
            }

            if ok == 1 {
                break;
            }

            tries += 1;
            if tries > 10 {
                return Err(GetRandomError::FAILED_RDRAND);
            }
        }

        let bytes = rnd.to_ne_bytes();
        for (b, r) in chunk.iter_mut().zip(bytes.iter()) {
            *b = *r;
        }
    }

    Ok(())
}
