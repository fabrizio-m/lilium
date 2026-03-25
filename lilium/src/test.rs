use ark_ff::Field;
use ccs::{
    circuit::{Circuit, Var},
    constraint_system::{ConstraintSystem, Val},
    gates::StandardGates,
};

enum Circuit1 {}

impl<F: Field> Circuit<F, 2, 1, 0> for Circuit1 {
    type PrivateInput = ();

    type PrivateOutput = ();

    fn circuit<V: Val, C: ConstraintSystem<F, V>>(
        cs: &mut C,
        public_input: [Var<V>; 2],
    ) -> ([Var<V>; 1], [Var<V>; 0]) {
        let [mut acc, base] = public_input;
        let exp = 32523u32;
        for i in (0..32).rev() {
            let new_acc = if ((exp >> i) & 0b1) == 0 {
                // println!("b1");
                acc
            } else {
                // println!("b2");
                cs.mul(acc, base.clone())
            };
            acc = cs.square(new_acc);
        }
        ([acc], [])
    }

    fn handle_output(_out: [F; 0]) -> Self::PrivateOutput {}
}

#[test]
fn test_end_to_end() {
    use crate::circuit_key::CircuitKey;
    use ark_ff::One;
    use ark_vesta::{Fr, Projective, VestaConfig};
    use hash_to_curve::svdw::SvdwMap;
    use sponge;

    type Scheme = commit::ipa::poly_comm::IpaCommitmentScheme<Fr, Projective, SvdwMap<VestaConfig>>;
    type Permutation = sponge::poseidon2::PoseidonDefault<Fr>;
    type Sponge = sponge::sponge::Sponge<Fr, Permutation, 1, 2, 3>;
    type Key = CircuitKey<Fr, Sponge, Circuit1, Scheme, 3, 3, 4>;

    println!("creating key..");
    let key: Key = Key::new();
    println!("key created");
    // let key = CircuitKey::<Fr, Sponge, Circuit1, Scheme, 1, 3, 10>::new::<_, _, _>();
    println!("proving..");
    let (instance, proof, _) = key.prove_from_inputs([Fr::one(), Fr::from(31u8)]);
    println!("proved");

    println!("verifying..");
    let verifies = key.verify(instance, proof);
    println!("verified");
    assert!(verifies);
}
