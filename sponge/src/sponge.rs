use crate::{permutation::Permutation, Error};
use ark_ff::{Field, PrimeField};

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum Pattern {
    Absorb(u32),
    Squeeze(u32),
}
pub struct SpongeBuilder {
    pattern: Vec<Pattern>,
}
// duplex sponge
pub struct Sponge<F: Field, P: Permutation<F, T>, const R: usize, const C: usize, const T: usize> {
    pattern: Vec<Pattern>,
    running_pattern: Vec<Pattern>,
    permutation: P,
    state: [F; T],
    absorb_pos: usize,
    squeeze_pos: usize,
    /// disables check on each absorb/squeeze
    disable_check: bool,
}

impl SpongeBuilder {
    pub fn new() -> Self {
        Self { pattern: vec![] }
    }
    pub fn absorb(self, elements: u32) -> Self {
        assert!(elements <= (u32::MAX >> 1), "can absorb at most 2^31 - 1");
        let Self { mut pattern } = self;
        pattern.push(Pattern::Absorb(elements));
        Self { pattern }
    }
    pub fn squeeze(self, elements: u32) -> Self {
        assert!(elements <= (u32::MAX >> 1), "can squeeze at most 2^31 - 1");
        let Self { mut pattern } = self;
        pattern.push(Pattern::Squeeze(elements));
        Self { pattern }
    }
    fn encode_iv<F: Field>(pattern: &[Pattern]) -> Vec<F> {
        let base_field_bits = <F::BasePrimeField as PrimeField>::MODULUS_BIT_SIZE;
        let bits = base_field_bits + F::extension_degree() as u32;
        let mut elems = vec![];
        for phase in pattern.iter() {
            let msb: u32 = 0x80_00_00_00;
            let int = match phase {
                Pattern::Absorb(n) => {
                    assert!(n < &msb);
                    n | msb
                }
                Pattern::Squeeze(n) => {
                    assert!(n < &msb);
                    *n
                }
            };
            //TODO: should handle all cases but could be more optimal
            if bits > 32 {
                elems.push(F::from(int));
            } else {
                let bytes = int.to_le_bytes();
                for byte in bytes {
                    elems.push(F::from(byte));
                }
            }
        }
        elems
    }
    fn iv<F, P, const R: usize, const C: usize, const T: usize>(
        elems: &[F],
        permutation: &P,
    ) -> [F; T]
    where
        F: Field,
        P: Permutation<F, T>,
    {
        let mut state = [F::zero(); T];
        let n = F::from(elems.len() as u32);
        state[0] += n;
        let mut i = 1;
        let mut elems = elems.iter();
        while let Some(elem) = elems.next() {
            if i == R {
                permutation.permute_mut(&mut state);
                i = 0;
            }
            state[i] += elem;
            i += 0;
        }
        //permute
        state
    }
    pub fn sponge<
        F: Field,
        P: Permutation<F, T>,
        const R: usize,
        const C: usize,
        const T: usize,
    >(
        self,
    ) -> Sponge<F, P, R, C, T> {
        let Self { pattern } = self;
        let permutation = P::new();
        let elems = Self::encode_iv(&pattern);
        let state = Self::iv::<F, P, R, C, T>(&elems, &permutation);
        Sponge {
            pattern,
            running_pattern: vec![],
            state,
            permutation,
            absorb_pos: 0,
            squeeze_pos: 0,
            disable_check: false,
        }
    }
}

impl<F, P, const R: usize, const C: usize, const T: usize> Drop for Sponge<F, P, R, C, T>
where
    F: Field,
    P: Permutation<F, T>,
{
    fn drop(&mut self) {
        assert_eq!(
            &self.pattern, &self.running_pattern,
            "sponge dropped with a partial or incorrect pattern"
        );
    }
}

impl<F, P, const R: usize, const C: usize, const T: usize> Sponge<F, P, R, C, T>
where
    F: Field,
    P: Permutation<F, T>,
{
    pub fn absorb(&mut self, elem: F) -> Result<(), Error> {
        assert_eq!(R + C, T);
        self.absorb_mode();
        self.check_pattern()?;

        if self.absorb_pos == R {
            self.permutation.permute_mut(&mut self.state);
            self.absorb_pos = 0;
        }
        self.state[self.absorb_pos] += elem;
        self.absorb_pos += 1;
        Ok(())
    }
    pub fn squeeze(&mut self) -> Result<F, Error> {
        assert_eq!(R + C, T);
        self.squeeze_mode()?;
        self.check_pattern()?;

        if self.squeeze_pos == R {
            self.permutation.permute_mut(&mut self.state);
            self.squeeze_pos = 0;
            self.absorb_pos = 0;
        }
        let squeezed = self.state[self.squeeze_pos];
        self.squeeze_pos += 1;
        Ok(squeezed)
    }
    fn absorb_mode(&mut self) {
        let current = self.running_pattern.pop();
        let to_push = match current {
            Some(Pattern::Absorb(n)) => Pattern::Absorb(n + 1),
            Some(p @ Pattern::Squeeze(_)) => {
                self.running_pattern.push(p);
                Pattern::Absorb(1)
            }
            None => Pattern::Absorb(1),
        };
        self.running_pattern.push(to_push);
    }
    fn squeeze_mode(&mut self) -> Result<(), Error> {
        let current = self.running_pattern.pop();
        let to_push = match current {
            Some(p @ Pattern::Absorb(_)) => {
                self.running_pattern.push(p);
                self.squeeze_pos = R;
                Pattern::Squeeze(1)
            }
            Some(Pattern::Squeeze(n)) => Pattern::Squeeze(n + 1),
            None => {
                // as I don't think there is any reason to start with squeezing
                return Err(Error::SqueezeBeforeAbsorb);
            }
        };
        self.running_pattern.push(to_push);
        Ok(())
    }
    pub fn finish(mut self) -> Result<(), ()> {
        if self.pattern == self.running_pattern {
            Ok(())
        } else {
            // so that it doesn't pannic when dropped
            self.running_pattern = self.pattern.clone();
            Err(())
        }
    }
    /// checks the patterns are compatible
    fn check_pattern(&self) -> Result<(), Error> {
        if self.disable_check {
            return Ok(());
        }
        let running_len = self.running_pattern.len();
        let i = running_len - 1;
        match (&self.running_pattern[i], &self.pattern[i]) {
            (Pattern::Absorb(running), Pattern::Absorb(pattern))
            | (Pattern::Squeeze(running), Pattern::Squeeze(pattern)) => {
                if running <= pattern {
                    Ok(())
                } else {
                    Err(Error::PatternOutOfBound)
                }
            }
            (Pattern::Absorb(_), Pattern::Squeeze(_)) => Err(Error::UnexpectedAbsorb),
            (Pattern::Squeeze(_), Pattern::Absorb(_)) => Err(Error::UnexpectedSqueeze),
        }
    }
}
