use ark_ec::ScalarMul;
use ark_ff::Field;

pub fn fold_vec<F: Field>(mut vec: Vec<F>, challs: [F; 2]) -> Vec<F> {
    assert!(vec.len().is_power_of_two());
    let half_len = vec.len() / 2;
    let [chall_l, chall_r] = challs;
    let (vec_l, vec_r) = vec.split_at_mut(half_len);
    for (l, r) in vec_l.iter_mut().zip(vec_r.iter()) {
        *l = *l * chall_l + *r * chall_r;
    }
    vec.truncate(half_len);
    vec
}

pub fn fold_basis<G>(vec: Vec<G::MulBase>, challs: [G::ScalarField; 2]) -> Vec<G::MulBase>
where
    G: ScalarMul,
{
    assert!(vec.len().is_power_of_two());
    let half_len = vec.len() / 2;
    let [chall_l, chall_r] = challs;
    let (basis_l, basis_r) = vec.split_at(half_len);

    let basis: Vec<G> = basis_l
        .iter()
        .zip(basis_r.iter())
        //TODO: use wnaf
        .map(|(l, r)| *l * chall_l + *r * chall_r)
        .collect();

    //TODO: Not sure if this as good as it could be, check later
    G::batch_convert_to_mul_base(&basis)
}

pub fn compute_inner_product<F: Field>(a: &[F], b: &[F]) -> F {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .fold(F::zero(), |acc, (a, b)| acc + *a * b)
}

/// Computes the vector of 2^n combinations of n challenges and their inverses
pub fn challenge_combinations<F: Field>(challs: &[F], challs_inv: &[F]) -> Vec<F> {
    assert_eq!(challs.len(), challs_inv.len());
    let zero: F = challs_inv.iter().cloned().product();
    let flips: Vec<F> = challs.iter().map(|x| x.square()).collect();
    let mut combinations = vec![F::zero(); 1 << challs.len()];
    combine_rec(&flips, zero, &mut combinations);
    combinations
}

pub fn combine_rec<F: Field>(flips: &[F], zero: F, vec: &mut [F]) {
    assert!(vec.len().is_power_of_two());
    let half_len = vec.len() / 2;
    if flips.is_empty() {
        vec[0] = zero;
    } else {
        let (low, high) = vec.split_at_mut(half_len);
        combine_rec(&flips[1..], zero, low);
        let flip = flips[0];
        for (l, r) in low.iter().zip(high.iter_mut()) {
            *r = flip * l;
        }
    }
}
