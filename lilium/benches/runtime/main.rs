use ark_ff::{Field, UniformRand};
use ark_vesta::{Fr, Projective, VestaConfig};
use ccs::circuit::BuildStructure;
use commit::CommmitmentScheme;
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
    SamplingMode,
};
use hash_to_curve::svdw::SvdwMap;
use lilium::{circuit_key::CircuitKey, testing::utils::HashChain};
use rand::{rngs::StdRng, Rng, SeedableRng};
use sponge::{self, sponge::Duplex};

type Scheme = commit::ipa::poly_comm::IpaCommitmentScheme<Fr, Projective, SvdwMap<VestaConfig>>;
type Permutation = sponge::poseidon2::PoseidonDefault<Fr>;
type Sponge = sponge::sponge::Sponge<Fr, Permutation, 1, 2, 3>;

fn size<const N: usize>() -> u32 {
    let profile = <HashChain<N> as BuildStructure<Fr, 1, 1, 1, 5>>::profile();
    let witness_size = profile.witness_length.next_power_of_two().ilog2();
    println!("N: {}, len: 2^{}", N, witness_size);
    witness_size
}

#[allow(dead_code)]
/// A selection of circuits whose size sits just below a power of 2.
/// From 2^12 to 2^21.
fn sizes() {
    fn boundary<const N1: usize, const N2: usize>() {
        let s1 = size::<N1>();
        let s2 = size::<N2>();
        println!("---------");
        assert_eq!(s1 + 1, s2);
    }
    boundary::<11, 12>();
    boundary::<22, 23>();
    boundary::<44, 45>();
    boundary::<89, 90>();
    boundary::<178, 179>();
    boundary::<356, 357>();
    boundary::<712, 713>();
    boundary::<1424, 1425>();
    boundary::<2849, 2850>();
    boundary::<5698, 5699>();
}

fn proving(c: &mut Criterion) {
    let mut group = c.benchmark_group("Proving Time");
    group.sampling_mode(SamplingMode::Flat);
    let mut rng = StdRng::seed_from_u64(0);
    prove::<11>(&mut group, &mut rng);
    prove::<22>(&mut group, &mut rng);
    prove::<44>(&mut group, &mut rng);
    prove::<89>(&mut group, &mut rng);
    prove::<178>(&mut group, &mut rng);
}

fn prove<const N: usize>(group: &mut BenchmarkGroup<'_, WallTime>, rng: &mut impl Rng)
where
    Fr: Field,
    Scheme: CommmitmentScheme<Fr>,
    Sponge: Duplex<Fr>,
{
    let preimage = Fr::rand(rng);
    let key = CircuitKey::<Fr, Sponge, HashChain<N>, Scheme, 2, 4, 5>::new();
    let profile = <HashChain<N> as BuildStructure<Fr, 1, 1, 1, 5>>::profile();

    group.bench_with_input(
        BenchmarkId::new("Proving", profile.witness_length),
        &key,
        |b, key| {
            b.iter(|| {
                let (_instance, _proof, _output) = key.prove_from_inputs([preimage]);
            });
        },
    );
}

criterion_group! {
    name = hash_chain;
    config = Criterion::default().sample_size(10);
    targets = proving
}
criterion_main!(hash_chain);
