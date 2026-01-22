use std::ops::Index;

///sparse matrix
#[derive(Default, Clone, Debug)]
pub struct Matrix {
    ///assumes each non zero value to be one, should be enough to represent plonk
    /// considering that most rows will likely have a single 1 the vector represation may be suboptimal
    rows: Vec<Vec<usize>>,
    //generalized version that supports arbitrary values
    //rows: Vec<Vec<(usize, F)>>,
}
impl Matrix {
    /// number of rows
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.len() == 0
    }

    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Matrix {
            rows: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn push_row_single_value(&mut self, idx: usize) {
        self.rows.push(vec![idx])
    }

    pub(crate) fn push_row_empty(&mut self) {
        self.rows.push(vec![])
    }

    /// convert to sparse indexed evals as expected by spark
    pub fn to_evals(&self) -> Vec<(usize, usize)> {
        let mut evals = Vec::with_capacity(self.rows.len());
        for (i, cols) in self.rows.iter().enumerate() {
            for col in cols {
                evals.push((i, *col));
            }
        }
        evals
    }

    /// Returns a reference to the row in the given position or `None`
    /// if out of bounds.
    pub fn get_row(&self, index: usize) -> Option<&[usize]> {
        self.rows.get(index).map(Vec::as_slice)
    }
}

impl Index<usize> for Matrix {
    type Output = [usize];

    fn index(&self, index: usize) -> &Self::Output {
        &self.rows[index]
    }
}
