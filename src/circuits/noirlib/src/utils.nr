use dep::std;

fn less_than(x: Field, y: Field) ->  bool {
    let x_bits = x.to_be_bytes(32);
    let y_bits = y.to_be_bytes(32);
    let mut res = 0;
    for i in  0..32 {
        if ((x_bits[i] < y_bits[i]) & (res == 0)) {
            res = 1;
        }
        else if ((x_bits[i] > y_bits[i]) & (res == 0)) {
            res = 2;
        }
    }
    res == 1
}

fn from_le_bits<N>(bits: [u1; N]) -> Field{
    let mut res: Field = 0;
    let mut mul2: Field = 1;
    for i in 0..N{
        if(bits[i] == 1){
            res = res + mul2;
        }

        mul2 = mul2 * 2;
    }

    res
}

fn from_le_bytes<N>(bytes: [u8;N]) -> Field{
    
    let mut res: Field = 0;
    let mut mul2: Field = 1;
    for i in 0..N{ 
        res = res + mul2 * (bytes[i] as Field);
        mul2 = mul2 * 256;
    }

    res
}


fn from_be_bytes(bytes: [u8; 32]) -> (Field, Field){
    let mut hi: Field = 0;
    let mut lo: Field = 0;
    for i in 0..16 {
        hi = 256 * hi + (bytes[i] as Field);
        lo = 256 * lo + (bytes[i + 16] as Field);
    }

    let res = (hi, lo);
    res
}

fn cal_root_from_mtp<N>(path: [Field; N], leaf: Field, index: Field) -> Field {
    let index_bits  = index.to_le_bits(N as u32);
    let mut current = leaf;
    for i in 0..N {
        let path_bit = index_bits[i] as bool;
        let (hash_left, hash_right) = if path_bit {
            (path[i], current)
         } else {
            (current, path[i])
         };

      current = std::hash::poseidon::bn254::hash_2([hash_left, hash_right]);
    };
    current
}

fn fields_to_u8_array<N, M>(x: [Field;N], mut z: [u8; M]) {
    for i in 0..N {
        let y = x[i].to_le_bytes(32);
        for j in 0..32 {
            z[i*32+j] = y[j];
        }
    }
}