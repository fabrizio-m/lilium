use core::slice;
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

    /// Returns iterator over all non-zero cells, panics if the matrix is empty.
    pub fn iter(&self) -> CellIter<'_> {
        let mut rows = self.rows.iter();
        let current_row = rows.next().expect("matrix is empty").iter();
        CellIter { rows, current_row }
    }
}

impl Index<usize> for Matrix {
    type Output = [usize];

    fn index(&self, index: usize) -> &Self::Output {
        &self.rows[index]
    }
}

/// Itertator over the cells of a matrix.
pub struct CellIter<'a> {
    rows: slice::Iter<'a, Vec<usize>>,
    current_row: slice::Iter<'a, usize>,
}

impl Iterator for CellIter<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        match self.current_row.next() {
            Some(c) => Some(*c),
            None => {
                let new_row = self.rows.next()?;
                let mut new_row = new_row.iter();
                let next = new_row.next();
                self.current_row = new_row;
                next.copied()
            }
        }
    }
}
