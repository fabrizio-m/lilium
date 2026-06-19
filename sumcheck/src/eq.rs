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
//! But a gray code has the issue of a rather unpredictable memory access if used
//! as an index, or having to sort the result at the end. And it doesn't seem
//! to even be necessary.
//!
//! The algorithem then looks like a gray code without the reversing part.
//! We start with eq(0,e), make 2 copies, keep one for 0 and modify the other
//! with a single multiplication to get 1.
//! Then having the 2 evaluations for 1 varible, we duplicate them, keep 1 copy
//! for 0x and modify the other copy into the 1x evaluations with 2 multiplications.
//! And so on we continue until having all the evaluations.

use crate::polynomials::MultiPoint;
use ark_ff::Field;
use std::ops::Mul;

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

// Here vars[i] is None for a coordinate equal to 1, otherwise it's the flip factor v_i/(1-v_i).
// A v == 1 coordinate contributes the factor x_i, so its level does no multiplication, but
// instead it zeroes the half-cube where its bit is 0 and passes the other half unchanged.
fn eval_eq<F: Field>(dest: &mut [F], mut vars: Vec<Option<F>>, zero: F) {
    assert!(dest.len().is_power_of_two());
    if dest.len() == 2 {
        assert_eq!(vars.len(), 1);
        match vars.pop().unwrap() {
            Some(flip) => {
                dest[0] = zero;
                dest[1] = zero * flip;
            }
            // v == 1: bit unset -> 0, bit set -> pass through (factor 1)
            None => {
                dest[0] = F::zero();
                dest[1] = zero;
            }
        }
    } else {
        assert_eq!(dest.len().ilog2() as usize, vars.len());
        let half_len = dest.len() / 2;
        let var = vars.pop().unwrap();
        let (left, right) = dest.split_at_mut(half_len);
        eval_eq(left, vars, zero);
        match var {
            Some(flip) => {
                for (l, r) in left.iter().zip(right.iter_mut()) {
                    // to avoid lsp false positive
                    let r: &mut F = r;
                    *r = flip * l;
                }
            }
            // v == 1: high bit set -> copy sub-table, high bit unset -> zero fill
            None => {
                right.copy_from_slice(left);
                left.fill(F::zero());
            }
        }
    }
}

/// Computes eq(x,point) for each x in 0..(2^vars)
pub fn eq<F: Field>(point: &MultiPoint<F>) -> Vec<F> {
    let n_log = point.vars();
    eq_subset(point, n_log)
}

/// Computes eq(x,point) for each x in 0..(2^n_log)
pub fn eq_subset<F: Field>(point: &MultiPoint<F>, n_log: usize) -> Vec<F> {
    // these are the values corresponding to a 1 in the corresponding bit
    let vars = point.inner_ref();
    assert!(vars.len() >= n_log, "subset bigger than full set");
    assert!(n_log > 0, "subset must not be empty");
    let len = 1 << n_log;
    // the values corresponding to a 0 in the corresponding bit
    let one_minus_v: Vec<F> = vars.iter().map(|x| F::one() - x).collect();
    // The inverse of above, multiplying by it will undo multiplying by the value.
    // The batch_inversion leaves any zero entries (i.e. v == 1) as 0; those are never
    // used because those coordinates become None flips below
    let mut one_minus_v_inv = one_minus_v[..n_log].to_vec();
    ark_ff::fields::batch_inversion(&mut one_minus_v_inv);
    // Flip factor v/(1-v) for each enumerated coordinate (sets a bit from 0 to 1), or None
    // for a coordinate equal to 1, which is handled without division (1 - v == 0  and  v == 1)
    let flips = vars
        .iter()
        .zip(one_minus_v_inv)
        .map(|(var, inv)| {
            if *var == F::one() {
                None
            } else {
                Some(*var * inv)
            }
        })
        .collect();

    // eq at the all-zeros point x = 0...0, i.e. the product of (1 - v) over every coordinate, except
    //     * skip enumerated (i < n_log) coordinates with v == 1 (handled by eval_eq's None branch),
    //     * keep coordinates beyond n_log (fixed to x = 0) because a v == 1 there correctly zeros the table.
    // Empty product (all coordinates skipped) equals 1.
    let zero: F = one_minus_v
        .iter()
        .enumerate()
        .filter(|(i, _)| *i >= n_log || vars[*i] != F::one())
        .map(|(_, one_minus_v)| *one_minus_v)
        .reduce(Mul::mul)
        .unwrap_or_else(F::one);

    let mut eq = Vec::with_capacity(len);
    eq.resize(len, F::zero());
    eval_eq(&mut eq, flips, zero);
    eq
}

#[test]
fn test_eq() {
    use crate::polynomials::{EvalsExt, SingleEval};
    use ark_vesta::Fr;
    use rand::{thread_rng, Rng};

    // let point = MultiPoint::r
    let mut rng = thread_rng();
    let mut r_point = || rng.gen::<Fr>();
    let vars = 4;
    let point = vec![r_point(); vars];
    let point = MultiPoint::new(point);

    let eq_evals = eq(&point);

    let check_poly = vec![r_point(); eq_evals.len()];

    let eq_eval = eq_evals
        .iter()
        .cloned()
        .zip(check_poly.iter())
        .fold(Fr::from(0), |sum, (a, b)| sum + a * b);

    let check_poly: Vec<_> = check_poly.into_iter().map(SingleEval).collect();
    let check_eval = EvalsExt::eval_slow(check_poly, point).0;
    assert_eq!(eq_eval, check_eval);
}

#[test]
fn test_subset() {
    use ark_vesta::Fr;
    let vars: [Fr; 4] = [2_u32, 3, 4, 5].map(Fr::from);
    let point: MultiPoint<Fr> = MultiPoint::new(vars.to_vec());

    let full_eq = eq(&point);
    let subset_eq = eq_subset(&point, 2);

    for i in 0..4 {
        assert_eq!(full_eq[i], subset_eq[i]);
    }
}
