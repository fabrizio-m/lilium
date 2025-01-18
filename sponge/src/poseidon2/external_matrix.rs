use ark_ff::Field;

// |5 7 1 3|
// |4 6 1 1|
// |1 3 5 7|
// |1 1 4 6|
#[allow(unused)]
fn m4<F: Field>(x: [F; 4]) -> [F; 4] {
    let t0 = x[0] + x[1];
    let t1 = x[2] + x[3];
    let t2 = x[1].double() + t1;
    let t3 = x[3].double() + t0;
    let t4 = t1.double().double() + t3;
    let t5 = t0.double().double() + t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    [t6, t5, t7, t4]
}
