//! Constant-time SRP modular exponentiation backed by RustCrypto fixed-width integers.
//!
//! The 3072-bit modulus is fixed by the HomeKit SRP group. Inputs are decoded
//! into fixed-width values, and secret intermediates are zeroized on drop.

use crypto_bigint::{
    Odd, U3072,
    modular::{FixedMontyForm, FixedMontyParams},
};
use zeroize::{Zeroize, Zeroizing};

const INTEGER_BYTES: usize = U3072::BYTES;
const MODULUS: Odd<U3072> = Odd::from_be_hex(super::srp::MODULUS_HEX);
const PARAMS: FixedMontyParams<{ U3072::LIMBS }> = FixedMontyParams::new(MODULUS);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SrpCtError {
    InputTooWide,
}

impl std::fmt::Display for SrpCtError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SRP integer exceeds the 3072-bit group width")
    }
}

impl std::error::Error for SrpCtError {}

fn decode_fixed(input: &[u8]) -> Result<Zeroizing<U3072>, SrpCtError> {
    if input.len() > INTEGER_BYTES {
        return Err(SrpCtError::InputTooWide);
    }

    let mut padded = Zeroizing::new([0u8; INTEGER_BYTES]);
    let offset = INTEGER_BYTES - input.len();
    padded[offset..].copy_from_slice(input);
    Ok(Zeroizing::new(U3072::from_be_slice(&padded[..])))
}

/// Compute base^exponent mod the HomeKit 3072-bit SRP modulus.
///
/// Exponentiation uses FixedMontyForm::pow, not its explicitly variable-time
/// pow_vartime counterpart. The returned fixed-width bytes are zeroized by
/// the caller when the result is no longer needed.
pub(super) fn modpow(
    base: &[u8],
    exponent: &[u8],
) -> Result<Zeroizing<[u8; INTEGER_BYTES]>, SrpCtError> {
    let base = decode_fixed(base)?;
    let exponent = decode_fixed(exponent)?;

    let montgomery = Zeroizing::new(FixedMontyForm::new(&base, &PARAMS));
    let powered = Zeroizing::new(montgomery.pow(&exponent));
    let result = Zeroizing::new(powered.retrieve());

    let mut encoded = result.to_be_bytes();
    let mut output = Zeroizing::new([0u8; INTEGER_BYTES]);
    output.copy_from_slice(encoded.as_ref());
    encoded.as_mut().zeroize();

    Ok(output)
}

/// Multiply two SRP group values modulo N using fixed-width Montgomery arithmetic.
pub(super) fn mul_mod(
    left: &[u8],
    right: &[u8],
) -> Result<Zeroizing<[u8; INTEGER_BYTES]>, SrpCtError> {
    let left = decode_fixed(left)?;
    let right = decode_fixed(right)?;
    let left = Zeroizing::new(FixedMontyForm::new(&left, &PARAMS));
    let right = Zeroizing::new(FixedMontyForm::new(&right, &PARAMS));
    encode_fixed(&left.mul(&right))
}

/// Add two SRP group values modulo N using fixed-width Montgomery arithmetic.
pub(super) fn add_mod(
    left: &[u8],
    right: &[u8],
) -> Result<Zeroizing<[u8; INTEGER_BYTES]>, SrpCtError> {
    let left = decode_fixed(left)?;
    let right = decode_fixed(right)?;
    let left = Zeroizing::new(FixedMontyForm::new(&left, &PARAMS));
    let right = Zeroizing::new(FixedMontyForm::new(&right, &PARAMS));
    encode_fixed(&left.add(&right))
}

/// Subtract two SRP group values modulo N using fixed-width Montgomery arithmetic.
pub(super) fn sub_mod(
    left: &[u8],
    right: &[u8],
) -> Result<Zeroizing<[u8; INTEGER_BYTES]>, SrpCtError> {
    let left = decode_fixed(left)?;
    let right = decode_fixed(right)?;
    let left = Zeroizing::new(FixedMontyForm::new(&left, &PARAMS));
    let right = Zeroizing::new(FixedMontyForm::new(&right, &PARAMS));
    encode_fixed(&left.sub(&right))
}

fn encode_fixed(
    value: &FixedMontyForm<{ U3072::LIMBS }>,
) -> Result<Zeroizing<[u8; INTEGER_BYTES]>, SrpCtError> {
    let retrieved = Zeroizing::new(value.retrieve());
    let mut encoded = retrieved.to_be_bytes();
    let mut output = Zeroizing::new([0u8; INTEGER_BYTES]);
    output.copy_from_slice(encoded.as_ref());
    encoded.as_mut().zeroize();
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{INTEGER_BYTES, SrpCtError, add_mod, modpow, mul_mod, sub_mod};
    use num_bigint::BigUint;

    fn modulus() -> BigUint {
        BigUint::parse_bytes(super::super::srp::MODULUS_HEX.as_bytes(), 16)
            .expect("valid HomeKit SRP modulus")
    }

    fn assert_matches_reference(base: &[u8], exponent: &[u8]) {
        let actual = modpow(base, exponent).expect("constant-time modular exponentiation");
        let base = BigUint::from_bytes_be(base);
        let exponent = BigUint::from_bytes_be(exponent);
        let expected = base.modpow(&exponent, &modulus()).to_bytes_be();

        assert!(expected.len() <= INTEGER_BYTES);
        assert_eq!(
            &actual[INTEGER_BYTES - expected.len()..],
            expected.as_slice()
        );
        assert!(
            actual[..INTEGER_BYTES - expected.len()]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn fixed_width_modpow_matches_biguint_reference_for_small_values() {
        assert_matches_reference(&[5], &[13]);
        assert_matches_reference(&[2], &[0x01, 0x23, 0x45, 0x67, 0x89]);
    }

    #[test]
    fn fixed_width_modpow_matches_reference_for_full_width_exponent() {
        let mut exponent = [0u8; 64];
        for (index, byte) in exponent.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17).wrapping_add(3);
        }
        assert_matches_reference(&[5], &exponent);
    }

    #[test]
    fn fixed_width_group_arithmetic_matches_biguint_reference() {
        let n = modulus();
        let left = BigUint::from(0x123456789abcdefu64);
        let right = BigUint::from(0xfedcba987654321u64);
        let left_bytes = left.to_bytes_be();
        let right_bytes = right.to_bytes_be();

        let product = mul_mod(&left_bytes, &right_bytes).unwrap();
        let expected_product = ((&left * &right) % &n).to_bytes_be();
        assert_eq!(
            &product[INTEGER_BYTES - expected_product.len()..],
            expected_product
        );

        let sum = add_mod(&left_bytes, &right_bytes).unwrap();
        let expected_sum = ((&left + &right) % &n).to_bytes_be();
        assert_eq!(&sum[INTEGER_BYTES - expected_sum.len()..], expected_sum);

        let difference = sub_mod(&right_bytes, &left_bytes).unwrap();
        let expected_difference = ((&right + &n - &left) % &n).to_bytes_be();
        assert_eq!(
            &difference[INTEGER_BYTES - expected_difference.len()..],
            expected_difference
        );
    }

    #[test]
    fn fixed_width_group_arithmetic_rejects_oversized_inputs() {
        let oversized = vec![1u8; INTEGER_BYTES + 1];
        assert_eq!(
            mul_mod(&oversized, &[1]).unwrap_err(),
            SrpCtError::InputTooWide
        );
        assert_eq!(
            add_mod(&[1], &oversized).unwrap_err(),
            SrpCtError::InputTooWide
        );
        assert_eq!(
            sub_mod(&[1], &oversized).unwrap_err(),
            SrpCtError::InputTooWide
        );
    }

    #[test]
    fn fixed_width_modpow_rejects_oversized_inputs() {
        let oversized = vec![1u8; INTEGER_BYTES + 1];
        assert_eq!(
            modpow(&oversized, &[2]).unwrap_err(),
            SrpCtError::InputTooWide
        );
        assert_eq!(
            modpow(&[2], &oversized).unwrap_err(),
            SrpCtError::InputTooWide
        );
    }
}
