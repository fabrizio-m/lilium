//! Grain LFSR

use automata::FiniteAutomaton;

pub(crate) struct Grain {
    low: u64,
    high: u16,
}

/// to select bits 0, 13, 23, 38, 51 and 62
const MASK: u64 = 0x40_08_00_40_00_80_20_01;

impl Grain {
    /*
    pub fn new(low: u64, high: u16) -> Self {
        Self { low, high }
    }
    pub fn print(&self) {
        print!("{:0>64b}", self.low.reverse_bits());
        println!("{:0>16b}", self.high.reverse_bits());
    }
        fn gen_byte(&mut self) -> u8 {
            for _ in 0..8 {
                let _ = self.cycle();
            }
            (self.high >> 8) as u8
        }
        pub fn discard(&mut self, n: usize) {
            for _ in 0..n {
                let _ = self.cycle();
            }
        }
    */
}

impl FiniteAutomaton for Grain {
    type Init = (u64, u16);

    type State = (u64, u16);

    type Input = ();

    type Output = bool;

    fn init(init: Self::Init) -> Self {
        let (low, high) = init;
        Grain { low, high }
    }

    fn transition_mut(&mut self, _input: Self::Input) -> Self::Output {
        // same as computing the xor of the 5 bits,
        // but faster and simpler, just count the ones.
        // xor is 1 if the number of 1s is odd.
        let bits_to_xor = self.low & MASK;
        let xor_of_bits = bits_to_xor.count_ones() % 2;
        self.low >>= 1;
        let bit_to_transfer = self.high & 0b1;
        self.low |= (bit_to_transfer as u64) << 63;
        self.high >>= 1;
        match xor_of_bits {
            0 => {
                self.high |= 0b0000_0000_0000_0000;
                false
            }
            _ => {
                self.high |= 0b1000_0000_0000_0000;
                true
            }
        }
    }
}
