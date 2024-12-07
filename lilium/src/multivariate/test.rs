use crate::multivariate::{
    compute::MvPoly,
    evaluate::{MvEvaluator, Op, OperandOrStack},
};
use ark_ff::{Field, UniformRand};
use ark_vesta::Fr;
use rand::{thread_rng, Rng};

type Poly = MvPoly<Fr, usize>;
type Evaluator = MvEvaluator<Fr, usize>;

const PRINT_OPS: bool = false;

/// degree 1 poly with given var and random coefficient
fn single_var_poly<R: Rng>(rng: &mut R, var: usize) -> Poly {
    Poly::new(var, Fr::rand(rng))
}
fn vars<R: Rng>(rng: &mut R) -> [(usize, bool); 8] {
    [0, 1, 2, 3, 4, 5, 6, 7].map(|i| (i, rng.gen()))
}
/// single-term higher degree poly with random variables and coefficient
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
        .fold(init, |acc, v| acc * &v)
}
/// random muli-term higher degree poly with
fn full_poly<R: Rng>(rng: &mut R) -> Poly {
    let init = high_degree(rng);
    (0..20)
        .into_iter()
        .map(|_| high_degree(rng))
        .fold(init, |acc, t| acc + &t)
}
fn print_ops(op: &'static str) {
    if PRINT_OPS {
        print!("{}", op);
    }
}
fn eval_poly(poly: &Poly, resolve: [Fr; 8]) -> Fr {
    print_ops("polynomial ops: ");
    poly.terms
        .iter()
        .map(|(vars, coeff)| {
            let vars: Fr = vars
                .vars
                .iter()
                .map(|(var, power)| {
                    for _ in 0..*power {
                        print_ops("*");
                    }
                    resolve[*var].pow([*power as u64])
                })
                .fold(None, |acc, t| match acc {
                    Some(acc) => {
                        print_ops("*");
                        Some(acc * t)
                    }
                    None => Some(t),
                })
                .unwrap();
            print_ops("*");
            vars * coeff
        })
        .fold(None, |acc, t| match acc {
            Some(acc) => {
                print_ops("+");
                Some(acc + t)
            }
            None => Some(t),
        })
        .unwrap()
}
fn eval_stack(evaluator: &Evaluator, point: [Fr; 8]) -> Fr {
    let mut operands = evaluator.operands.iter();
    let operations = evaluator.operations.iter();
    let mut stack = vec![];
    print_ops("evaluator ops:  ");
    for operation in operations {
        match operation {
            Op::Add(operand_or_stack) => {
                let op1 = match operand_or_stack {
                    OperandOrStack::Operand => {
                        let (coeff, var) = operands.next().unwrap();
                        print_ops("*");
                        point[*var] * coeff
                    }
                    OperandOrStack::Stack => stack.pop().unwrap(),
                };
                let op2 = stack.pop().unwrap();
                print_ops("+");
                stack.push(op1 + op2);
            }
            Op::Mul(var) => {
                print_ops("*");
                let op = stack.pop().unwrap();
                stack.push(point[*var] * op);
            }
            Op::OperandToStack => {
                let (coeff, var) = operands.next().unwrap();
                print_ops("*");
                stack.push(point[*var] * coeff);
            }
        }
    }
    assert_eq!(stack.len(), 1);
    stack.pop().unwrap()
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
        // println!();
        // println!("evaluator: \n{:?}", evaluator);
        // println!();

        let mut point = || [(); 8].map(|_| Fr::rand(&mut rng));
        for _ in 0..1 {
            let point: [Fr; 8] = point();
            // eval by simple method
            let eval_tree = eval_poly(&poly, point);
            print_ops("\n");
            // eval using evaluator
            let eval_stack = eval_stack(&evaluator, point);
            print_ops("\n\n");
            assert_eq!(eval_tree, eval_stack);
        }
    }
}
