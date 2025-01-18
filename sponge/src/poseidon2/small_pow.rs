//! small exponent exponentiation

use ark_ff::Field;

// compiler should be able to optimize this for the given P
pub fn pow<F: Field, const P: u8>(val: F) -> F {
    let zero = F::zero();
    let x = val;
    let xx = x * x;
    let xxx = xx * x;

    let select = |p: u8| match p {
        0 => zero,
        1 => x,
        2 => xx,
        3 => xxx,
        _ => unreachable!(),
    };

    let pow = if (P & 0b11000000) == 0 {
        zero
    } else {
        let pow = select((P & 0b11000000) >> 6);
        pow.square().square()
    };
    let pow = if (P & 0b11110000) == 0 {
        zero
    } else {
        let pow = pow + select((P & 0b00110000) >> 4);
        pow.square().square()
    };
    let pow = if (P & 0b11111100) == 0 {
        zero
    } else {
        let pow = pow + select((P & 0b00001100) >> 2);
        pow.square().square()
    };
    pow + select(P & 0b11)
}
