use tfhe::gadget::{ciphertext::Ciphertext, server_key::ServerKey};

fn auction_circuit(
    server_key: &ServerKey,
    bids: &Vec<Vec<Ciphertext>>,
    bid_bits: usize,
    bidder_count: usize,
) -> Result<(Vec<Ciphertext>, Vec<Ciphertext>), Box<dyn std::error::Error>> {
    //TODO: check bids are correctly formed

    let mut w = vec![Ciphertext::Trivial(true); bidder_count];
    let mut s = vec![Ciphertext::Placeholder; bidder_count];
    let mut amount = vec![Ciphertext::Placeholder; bid_bits];
    for i in 0..bid_bits {
        // let now = std::time::Instant::now();
        for j in 0..bidder_count {
            // AND at i^th MSB of j^th bidder
            s[j] = server_key.and(&w[j], &bids[j][i])?;
        }

        // OR
        let b = {
            let mut b = server_key.or(&s[0], &s[1])?;
            for j in 2..bidder_count {
                b = server_key.or(&b, &s[j])?;
            }
            b
        };

        //  We require a multiplexer here and there are few ways to implement it:
        // 1. Circuit bootstrapping: Circuit bootstrap $b$ to a GGSW ciphertext and then use a single CMUX operation. However circuit bootstrapping itself requires $pbslevel$  bootstrapping operations + $pbslevel$ LWE -> RLWE key switching operations. Moreover, it requires private functional key switching keys. I don't think circuit bootstrapping improves runtime significantly such that it is worth it deal with its complexity + introducing more keys.
        // 2. Switch to 7-encoding space: In 7-encoding space this operation can be evaluated as single bootstrapping operation. However, p=7 requires 3 bit plaintext space thus doubling the bootstrapping runtime as compared to 2 bit plaintext space. Let bootstrapping runtime with 2-bit plaintext be x. Then evaluating AND + OR + MULTIPLEXER (MULTIPLEXER = $bs$ + $!bw$) takes 5x. With 3-bit plaintext space bootstrapping runtime equals 2x. Evaluating AND + OR + MULTIPLEXER (MULTIPLEXER is a single bootstrap) takes 5x. Thus, there's no benefit of switching to 7-encoding space.
        // 3. Rewriting multiplexer as $b * (s - w) + w$: This assumes ciphertexts are in canonical encoding (i.e. either 0/1 instead of 1/2). Switching from 1/2 to 0/1 is trivial since it requires a single plaintext subtraction by 1. However,  $s - w$ may equal -1 which will equal 2 in modulus 3. This forces lookup table to output to different values at same input (input: 1,0), which isn't possible.
        // 4. Naively implementation the multiplexer as $b s || !bw$: We implement this for now. However this requires 3 bootstrapping operations causing this to be the most expensive part of the circuit.
        // 5. Decrypting $b$: Since $b$ has to decrypted anyways to learn amount (assuming highest price auction), decrypting it before evaluating the multiplexer can save us from implementation it.
        // AND to reset w
        let b_not = server_key.not(&b);
        for j in 0..bidder_count {
            // (b & s[j]) + (!b & w[j])
            let c0 = server_key.and(&b, &s[j])?;
            let c1 = server_key.and(&b_not, &w[j])?;
            w[j] = server_key.or(&c0, &c1)?;
        }
        // println!("Time i:{i} - {}", now.elapsed().as_millis());
        // set i^th MSB of amount
        amount[i] = b;
    }

    Ok((w, amount))
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};
    use tfhe::gadget::{boolean::BOOLEAN_PARAMETERS, gen_keys};

    use super::*;

    #[test]
    fn auction_circuit_works() -> Result<(), Box<dyn std::error::Error>> {
        let bidders = 50;
        let BID_BITS = 64;

        let bids = (0..bidders)
            .into_iter()
            .map(|_| thread_rng().gen::<u64>())
            .collect::<Vec<u64>>();

        // generate FHE keys
        let (client_key, server_key) = gen_keys(&BOOLEAN_PARAMETERS);

        // encrypt bids
        let encrypts_bid_vector = bids
            .iter()
            .map(|bid_amount| {
                // encrypt bits from MSB to LSB
                (0..BID_BITS)
                    .into_iter()
                    .map(|i| {
                        let bit_i = (bid_amount >> (BID_BITS - 1 - i)) & 1;
                        client_key.encrypt(bit_i != 0)
                    })
                    .collect::<Vec<Ciphertext>>()
            })
            .collect::<Vec<Vec<Ciphertext>>>();

        let now = std::time::Instant::now();
        let (winner_identity_bit, winning_amount_bits) =
            auction_circuit(&server_key, &encrypts_bid_vector, BID_BITS, bidders)?;
        println!("Auction runtime: {}ms", now.elapsed().as_millis());

        // find the highest bidder amount
        let expected_highest_bid_amount = bids.iter().max().unwrap();
        let mut expected_highest_bidder_identity = vec![];
        bids.iter().enumerate().for_each(|(index, bid)| {
            if bid == expected_highest_bid_amount {
                expected_highest_bidder_identity.push(index);
            }
        });

        // check correctness
        // construct highest bidding amout returned from auction circuit
        let mut res_highest_bid_amount = 0u64;
        // winning amounts bits are stored from MSB to LSB
        winning_amount_bits
            .iter()
            .enumerate()
            .for_each(|(index, ct)| {
                let bit = client_key.decrypt(ct);
                res_highest_bid_amount =
                    res_highest_bid_amount + ((bit as u64) << (BID_BITS - 1 - index));
            });

        // find returned winner id
        let mut res_highest_bidder_identity = vec![];
        winner_identity_bit
            .iter()
            .enumerate()
            .for_each(|(index, bit_ct)| {
                let bit = client_key.decrypt(bit_ct);
                if bit {
                    res_highest_bidder_identity.push(index);
                }
            });

        dbg!(expected_highest_bid_amount, res_highest_bid_amount);
        dbg!(
            &expected_highest_bidder_identity,
            &res_highest_bidder_identity
        );

        assert_eq!(*expected_highest_bid_amount, res_highest_bid_amount);
        assert_eq!(
            expected_highest_bidder_identity,
            res_highest_bidder_identity
        );

        Ok(())
    }
}
