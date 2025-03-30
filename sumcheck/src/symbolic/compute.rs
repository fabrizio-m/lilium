use ark_ff::Field;
use std::{
    collections::BTreeMap,
    ops::{Add, Mul, Neg, Sub},
};

/// Multivariate polynomial
#[derive(Clone, Debug)]
pub struct MvPoly<F: Field, V: Eq + Ord> {
    // (vars, constant)
    pub terms: Vec<(MvPolyTerm<V>, F)>,
}

impl<F: Field, V: Eq + Ord> Default for MvPoly<F, V> {
    fn default() -> Self {
        Self { terms: vec![] }
    }
}

/// A term, with only non-zero variables present
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct MvPolyTerm<V: Eq + Ord> {
    // (var, power)
    pub vars: BTreeMap<V, usize>,
}

impl<V: Eq + Ord + Clone> MvPolyTerm<V> {
    pub fn degree(&self) -> usize {
        self.vars.iter().map(|x| x.1).sum()
    }
    pub fn has_var(&self, var: &V) -> bool {
        self.vars.contains_key(var)
    }
    pub fn remove_var(&mut self, var: &V) {
        match self.vars.remove(var) {
            Some(0) => {
                panic!("power is zero, shouldn't be zero");
            }
            Some(1) => {}
            Some(n) => {
                self.vars.insert(var.clone(), n - 1);
            }
            None => {
                panic!("variable not present");
            }
        }
    }
    /// Returns the single var if degree 1 or panics
    pub fn unwrap_single_var(self) -> V {
        assert_eq!(self.degree(), 1);
        self.vars.keys().next().unwrap().clone()
    }
}

// Multiplication between 2 terms
impl<V: Eq + Clone + Ord> Mul for &MvPolyTerm<V> {
    type Output = MvPolyTerm<V>;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut product: BTreeMap<V, usize> = self.vars.clone();
        for (var, power) in rhs.vars.iter() {
            *product.entry(var.clone()).or_insert(0) += power;
        }
        let vars = product.into_iter().collect();
        MvPolyTerm { vars }
    }
}

impl<F: Field, V> Add<&Self> for MvPoly<F, V>
where
    V: Eq + Ord + Clone,
{
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        let mut sum: BTreeMap<MvPolyTerm<V>, F> = self.terms.into_iter().collect();
        for (term, constant) in rhs.terms.iter().cloned() {
            let term = sum.entry(term).or_insert(F::zero());
            *term += constant;
        }
        let terms = sum.into_iter().filter(|x| !x.1.is_zero()).collect();
        Self { terms }
    }
}

impl<F: Field, V> Mul<&Self> for MvPoly<F, V>
where
    V: Eq + Ord + Clone,
{
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        let mut product = MvPoly::default();
        for (lterm, lconst) in self.terms.into_iter() {
            let terms = rhs
                .terms
                .iter()
                .map(|(rterm, rconst)| (rterm * &lterm, lconst * rconst))
                .collect();
            let partial_product = MvPoly { terms };
            product = product + &partial_product;
        }
        product
    }
}

impl<F: Field, V: Eq + Ord> Neg for MvPoly<F, V> {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        for (_, constant) in self.terms.iter_mut() {
            // due to lsp false positive
            let constant: &mut F = constant;
            *constant = -(*constant);
        }
        self
    }
}

impl<F: Field, V> Sub for MvPoly<F, V>
where
    V: Eq + Ord + Clone,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let rhs = -rhs;
        self + (&rhs)
    }
}

impl<F: Field, V: Eq + Ord> MvPoly<F, V> {
    pub fn new(var: V, coeff: F) -> Self {
        let vars = BTreeMap::from([(var, 1)]);
        let term = MvPolyTerm { vars };
        let terms = vec![(term, coeff)];
        MvPoly { terms }
    }
}
