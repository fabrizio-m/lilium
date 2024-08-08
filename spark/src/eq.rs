//! To eq(x,e) polynomial for n variables has this shape
//!          n-1
//! eq(x,e) = 𝜫 (xi * ei + (1 - xi)(1 - ei))
//!          i=0
//! it can be cheaply evaluated in a point, but evaluating it over
//! the 2^n points of the domain require n*log(n) multiplications if
//! done point by point and precomputing each 1-ei
//!
//! The original idea was to iterate a gray code so that each element
//! differs from the previous one in only one bit, then we can use that
//! previous element to compute the current one with only 1 multiplication
//! to swap the bit in question.
//! But a gray has the issue of a rather unpredictable memory access if used
//! as an index, or having to sort the result at the end. And it doens't seem
//! to even be necessary.
//!
//! The algorithem then looks like a gray code without the reversing part.
//! We start with eq(0,e), make 2 copies, keep one for 0 and modify the other
//! with a single multiplication to get 1.
//! Then having the 2 evaluations for 1 varible, we duplicate them, keep 1 copy
//! for 0x and modify the other copy into the 1x evaluations with 2 multiplications.
//! And so on we continue until having all the evaluations.

use ark_ff::Field;
use std::ops::Mul;
use sumcheck::polynomials::MultiPoint;

// computing a gray code as example, ultimately not used as
// there was a simpler and better way.
/*fn write_code(v: &mut [u32]) {
    assert!(v.len().is_power_of_two());
    if v.len() == 2 {
        v[0] = 0;
        v[1] = 1;
        return;
    }
    let half_len = v.len() / 2;
    let (left, right) = v.split_at_mut(half_len);
    write_code(left);
    let prefix = half_len as u32;
    for (l, r) in left.iter().zip(right.iter_mut().rev()) {
        //add proper shift
        *r = l | prefix;
    }
}

#[test]
fn gray() {
    let len = 1 << 3;
    let mut gray_code = vec![0; len];
    write_code(&mut gray_code);
    println!("code:");
    for e in gray_code {
        println!("{:#b}", e);
    }
}*/

fn eval_eq<F: Field>(dest: &mut [F], mut vars: Vec<F>, zero: F) {
    assert!(dest.len().is_power_of_two());
    if dest.len() == 2 {
        assert_eq!(vars.len(), 1);
        let var = vars.pop().unwrap();
        dest[0] = zero;
        dest[1] = zero * var;
    } else {
        assert_eq!(dest.len().ilog2() as usize, vars.len());
        let half_len = dest.len() / 2;
        let var = vars.pop().unwrap();
        let (left, right) = dest.split_at_mut(half_len);
        eval_eq(left, vars, zero);
        for (l, mut r) in left.iter().zip(right.iter_mut()) {
            *r = var * l;
        }
    }
}

pub fn eq<F: Field>(vars: MultiPoint<F>) -> Vec<F> {
    // this are the values corresponding to a 1 in the corresponding bit
    let v = vars.inner();
    let len = 1 << v.len();
    // this are the values corresponding to a 0 in the corresponding bit
    let one_minus_v: Vec<F> = v.iter().map(|x| F::one() - x).collect();
    // the inverse of the previous, multiplying by it would undo the previous
    let mut one_minus_v_inv = one_minus_v.clone();
    ark_ff::fields::batch_inversion(&mut one_minus_v_inv);
    // this have the effect of setting the value of an evaluation from 0 to 1
    // for any particular bit.
    // combines the effect of v and one_minus_v_inv
    let vars: Vec<F> = v.iter().zip(one_minus_v_inv).map(|(a, b)| *a * b).collect();

    let zero: F = one_minus_v.iter().cloned().reduce(Mul::mul).unwrap();
    let mut eq = Vec::with_capacity(len);
    eq.resize(len, F::zero());
    eval_eq(&mut eq, vars, zero);
    eq
}

#[test]
fn test_eq() {
    use ark_vesta::Fr;
    use rand::{thread_rng, Rng};
    use sumcheck::polynomials::{EvalsExt, SingleEval};

    // let point = MultiPoint::r
    let mut rng = thread_rng();
    let mut r_point = || rng.gen::<Fr>();
    let vars = 4;
    let point = vec![r_point(); vars];
    let point = MultiPoint::new(point);

    let eq_evals = eq(point.clone());

    let check_poly = vec![r_point(); eq_evals.len()];

    let eq_eval = eq_evals
        .iter()
        .cloned()
        .zip(check_poly.iter())
        .fold(Fr::from(0), |sum, (a, b)| sum + a * b);

    let check_poly: Vec<_> = check_poly.into_iter().map(SingleEval).collect();
    let check_eval = EvalsExt::eval(check_poly, point).0;
    assert_eq!(eq_eval, check_eval);
}
