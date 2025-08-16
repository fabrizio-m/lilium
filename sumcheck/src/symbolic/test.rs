use crate::symbolic::{
    compute::MvPoly,
    evaluate::{MvEvaluator, MvIr},
};
use ark_ff::{Field, UniformRand};
use ark_vesta::Fr;
use automata::memory_machine::Memory;
use rand::{thread_rng, Rng};

type Poly = MvPoly<Fr, usize>;
type Evaluator = MvEvaluator<Fr, usize>;

const PRINT_OPS: bool = false;

/// Degree 1 poly with given var and random coefficient.
fn single_var_poly<R: Rng>(rng: &mut R, var: usize) -> Poly {
    Poly::new(var, Fr::rand(rng))
}

/// Generate random point to check evaluation.
fn vars<R: Rng>(rng: &mut R) -> [(usize, bool); 8] {
    [0, 1, 2, 3, 4, 5, 6, 7].map(|i| (i, rng.gen()))
}

/// single-term higher degree poly with random variables and coefficient.
fn high_degree<R: Rng>(rng: &mut R) -> Poly {
    let vars = vars(rng);
    let init = single_var_poly(rng, 0);
    vars.into_iter()
        .filter_map(|(i, ignore)| {
            if ignore {
                None
            } else {
                Some(single_var_poly(rng, i))
            }
        })
        .fold(init, |acc, v| acc * v)
}

/// Random multi-term higher degree poly.
fn full_poly<R: Rng>(rng: &mut R) -> Poly {
    let init = high_degree(rng);
    (0..20)
        .map(|_| high_degree(rng))
        .fold(init, |acc, t| acc + t)
}

/// Print only in case of PRINT_OPS set.
fn print_ops(op: &'static str) {
    if PRINT_OPS {
        print!("{}", op);
    }
}

/// Eval using naive method.
fn eval_poly(poly: &Poly, resolve: [Fr; 8]) -> Fr {
    print_ops("polynomial ops: ");
    let mut muls1 = 0;
    let mut muls2 = 0;
    let eval = poly
        .terms
        .iter()
        .map(|(vars, coeff)| {
            let vars: Fr = vars
                .vars
                .iter()
                .map(|(var, power)| {
                    for _ in 0..*power {
                        print_ops("*");
                        muls1 += 1;
                    }
                    resolve[*var].pow([*power as u64])
                })
                .fold(None, |acc, t| match acc {
                    Some(acc) => {
                        print_ops("*");
                        muls2 += 1;
                        Some(acc * t)
                    }
                    None => Some(t),
                })
                .unwrap();
            print_ops("*");
            muls2 += 1;
            vars * coeff
        })
        .fold(None, |acc, t| match acc {
            Some(acc) => {
                print_ops("+");
                Some(acc + t)
            }
            None => Some(t),
        })
        .unwrap();
    let muls = muls1 + muls2;
    if PRINT_OPS {
        println!("\nmuls: {muls}");
    }
    eval
}

/// Count mul and add operations.
fn count_ops(evaluator: &Evaluator) {
    let program = evaluator.program();
    print_ops("evaluator ops:  ");
    let mut muls = 0;
    for instruction in program {
        let op = match instruction {
            MvIr::PushChild(_, _) => "*",
            MvIr::Add => "+",
            MvIr::Mul(_) => "*",
            MvIr::AddConstantTerm(_) => "+",
        };
        if op == "*" {
            muls += 1;
        }
        print_ops(op);
    }
    if PRINT_OPS {
        println!("\nmuls: {muls}");
    }
}

/// Simple memory.
struct Mem<F> {
    mem: Vec<F>,
}

impl<F> Mem<F> {
    fn new(mem: Vec<F>) -> Self {
        Self { mem }
    }
}

impl<F: Copy> Memory<usize, F> for Mem<F> {
    fn read(&self, address: usize) -> F {
        self.mem[address]
    }
}

/// Eval using stack machines.
fn eval_stack(evaluator: &Evaluator, point: [Fr; 8]) -> Fr {
    let memory = Mem::new(point.to_vec());
    evaluator.eval(&memory)
}

/// creates 10 random polynomials and evaluates them in 10 random points,
/// then checks the evaluations are equal.
#[test]
fn eval_mv_poly() {
    let mut rng = thread_rng();
    for _ in 0..10 {
        let poly = full_poly(&mut rng);
        let evaluator = MvEvaluator::new(poly.clone());
        // println!("poly: \n{:?}", poly);
        // println!("evaluator: \n{:?}", evaluator);

        let mut point = || [(); 8].map(|_| Fr::rand(&mut rng));

        for _ in 0..1 {
            let point: [Fr; 8] = point();
            // eval by simple method
            let eval_tree = eval_poly(&poly, point);
            let eval_stack = eval_stack(&evaluator, point);
            count_ops(&evaluator);
            print_ops("\n\n");
            assert_eq!(eval_tree, eval_stack);
        }
    }
}
