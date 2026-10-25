use pyo3::{prelude::*, exceptions::PyValueError};
use pyo3::types::{PyBytes, PyType};
use num_bigint::BigInt;
use num_integer::Integer;
use std::sync::LazyLock;

static SCALAR_PERIOD: LazyLock<BigInt> = LazyLock::new(|| {
    BigInt::from_bytes_be(
        num_bigint::Sign::Plus,
        &[
            0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1,
            0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x01,
        ],
    )
});

const BLST_P1_COMPRESSED_SIZE: usize = 48;

const BLST_P2_COMPRESSED_SIZE: usize = 96;

#[derive(Debug, Clone, PartialEq, thiserror::Error, miette::Diagnostic)]
pub enum Error {
    #[error("blst error {0:?}")]
    Blst(blst::BLST_ERROR),
    #[error("blst::hashToGroup")]
    HashToCurveDstTooBig,
}


impl std::convert::From<Error> for PyErr {
    fn from(err: Error) -> PyErr {
        PyValueError::new_err(format!("blst error {:?}", err))
    }
}


#[pyclass]
#[derive(Clone)]
pub struct BlstP1Element {
    _val: blst::blst_p1,
}

#[pyclass]
#[derive(Clone)]
pub struct BlstP2Element {
    _val: blst::blst_p2,
}

#[pyclass]
#[derive(Clone)]
pub struct BlstFP12Element {
    _val: blst::blst_fp12,
}




// Compressable trait and implementations taken over with thanks from aiken
// https://github.com/aiken-lang/aiken/blob/e1d46fa8f063445da8c0372e3c031c8a11ad0b14/crates/uplc/src/machine/runtime.rs#L1769C1-L1855C2
pub trait Compressable {
    fn compress(&self) -> Vec<u8>;

    fn uncompress(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: std::marker::Sized;
}

impl Compressable for blst::blst_p1 {
    fn compress(&self) -> Vec<u8> {
        let mut out = [0; BLST_P1_COMPRESSED_SIZE];

        unsafe {
            blst::blst_p1_compress(&mut out as *mut _, self);
        };

        out.to_vec()
    }

    fn uncompress(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BLST_P1_COMPRESSED_SIZE {
            return Err(Error::Blst(blst::BLST_ERROR::BLST_BAD_ENCODING));
        }

        let mut affine = blst::blst_p1_affine::default();

        let mut out = blst::blst_p1::default();

        unsafe {
            let err = blst::blst_p1_uncompress(&mut affine as *mut _, bytes.as_ptr());

            if err != blst::BLST_ERROR::BLST_SUCCESS {
                return Err(Error::Blst(err));
            }

            blst::blst_p1_from_affine(&mut out as *mut _, &affine);

            let in_group = blst::blst_p1_in_g1(&out);

            if !in_group {
                return Err(Error::Blst(blst::BLST_ERROR::BLST_POINT_NOT_IN_GROUP));
            }
        };

        Ok(out)
    }
}

impl Compressable for blst::blst_p2 {
    fn compress(&self) -> Vec<u8> {
        let mut out = [0; BLST_P2_COMPRESSED_SIZE];

        unsafe {
            blst::blst_p2_compress(&mut out as *mut _, self);
        };

        out.to_vec()
    }

    fn uncompress(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BLST_P2_COMPRESSED_SIZE {
            return Err(Error::Blst(blst::BLST_ERROR::BLST_BAD_ENCODING));
        }

        let mut affine = blst::blst_p2_affine::default();

        let mut out = blst::blst_p2::default();

        unsafe {
            let err = blst::blst_p2_uncompress(&mut affine as *mut _, bytes.as_ptr());

            if err != blst::BLST_ERROR::BLST_SUCCESS {
                return Err(Error::Blst(err));
            }

            blst::blst_p2_from_affine(&mut out as *mut _, &affine);

            let in_group = blst::blst_p2_in_g2(&out);

            if !in_group {
                return Err(Error::Blst(blst::BLST_ERROR::BLST_POINT_NOT_IN_GROUP));
            }
        };

        Ok(out)
    }
}

#[pymethods]
impl BlstP1Element {
    #[new]
    fn new() -> Self {
        BlstP1Element {
            _val: blst::blst_p1::default(),
        }
    }

    fn compress(&self) -> Vec<u8> {
        self._val.compress()
    }

    #[classmethod]
    fn uncompress(_: &Bound<'_, PyType>, arg1: Bound<'_, PyBytes>) -> Result<Self, Error> {
        let out = blst::blst_p1::uncompress(&arg1.as_bytes())?;
        Ok(BlstP1Element { _val: out })
    }
    fn __add__(
        &self,
        arg2: BlstP1Element,
    ) -> PyResult<BlstP1Element> {
        let arg1 = self;
        let mut out = blst::blst_p1::default();

        unsafe {
            blst::blst_p1_add_or_double(
                &mut out as *mut _,
                &arg1._val as *const _,
                &arg2._val as *const _,
            );
        }
        return Ok(BlstP1Element { _val: out });
    }

    fn __neg__(&self) -> PyResult<BlstP1Element> {
        let mut out = self._val.clone();
        unsafe {
            blst::blst_p1_cneg(&mut out as *mut _, true);
        }
        return Ok(BlstP1Element { _val: out });
    }

    fn scalar_mul(
        &self,
        arg: BigInt,
    ) -> PyResult<BlstP1Element> {
        // Taken from aiken implementation, not clear if this is just mul or more operations
        let arg1 = arg;
        let arg2 = &self._val;
        let size_scalar = size_of::<blst::blst_scalar>();

        let arg1 = arg1.mod_floor(&SCALAR_PERIOD);

        let (_, mut arg1) = arg1.to_bytes_be();

        if size_scalar > arg1.len() {
            let diff = size_scalar - arg1.len();

            let mut new_vec = vec![0; diff];

            new_vec.append(&mut arg1);

            arg1 = new_vec;
        }

        let mut out = blst::blst_p1::default();
        let mut scalar = blst::blst_scalar::default();

        unsafe {
            blst::blst_scalar_from_bendian(
                &mut scalar as *mut _,
                arg1.as_ptr() as *const _,
            );

            blst::blst_p1_mult(
                &mut out as *mut _,
                arg2 as *const _,
                scalar.b.as_ptr() as *const _,
                size_scalar * 8,
            );
        }
        Ok(BlstP1Element { _val: out })
    }

    fn __eq__(&self, other: &BlstP1Element) -> PyResult<bool> {
        let arg1 = &self._val;
        let arg2 = &other._val;
        let is_equal = unsafe { blst::blst_p1_is_equal(arg1, arg2) };
        Ok(is_equal)
    }

    #[classmethod]
    fn hash_to_group(
        _: &Bound<'_, PyType>,
        arg1: Bound<'_, PyBytes>,
        arg2: Bound<'_, PyBytes>,
    ) -> PyResult<BlstP1Element> {
        let dst = arg1.as_bytes();
        let msg = arg2.as_bytes();

        if msg.len() > 255 {
            return Err(Error::HashToCurveDstTooBig.into());
        }

        let mut out = blst::blst_p1::default();
        let aug = [];

        unsafe {
            blst::blst_hash_to_g1(
                &mut out as *mut _,
                dst.as_ptr(),
                dst.len(),
                msg.as_ptr(),
                msg.len(),
                aug.as_ptr(),
                0,
            );
        };

        Ok(BlstP1Element { _val: out} )
    }
    
}

#[pymethods]
impl BlstP2Element {
    #[new]
    fn new() -> Self {
        BlstP2Element {
            _val: blst::blst_p2::default(),
        }
    }

    fn compress(&self) -> Vec<u8> {
        self._val.compress()
    }

    #[classmethod]
    fn uncompress(_: &Bound<'_, PyType>, arg1: Bound<'_, PyBytes>) -> Result<Self, Error> {
        let out = blst::blst_p2::uncompress(&arg1.as_bytes())?;
        Ok(BlstP2Element { _val: out })
    }
    fn __add__(
        &self,
        arg2: BlstP2Element,
    ) -> PyResult<BlstP2Element> {
        let arg1 = self;
        let mut out = blst::blst_p2::default();

        unsafe {
            blst::blst_p2_add_or_double(
                &mut out as *mut _,
                &arg1._val as *const _,
                &arg2._val as *const _,
            );
        }
        return Ok(BlstP2Element { _val: out });
    }

    fn __neg__(&self) -> PyResult<BlstP2Element> {
        let mut out = self._val.clone();
        unsafe {
            blst::blst_p2_cneg(&mut out as *mut _, true);
        }
        return Ok(BlstP2Element { _val: out });
    }

    fn scalar_mul(
        &self,
        arg: BigInt,
    ) -> PyResult<BlstP2Element> {
        // Taken from aiken implementation, not clear if this is just mul or more operations
        let arg1 = arg;
        let arg2 = &self._val;
        let size_scalar = size_of::<blst::blst_scalar>();

        let arg1 = arg1.mod_floor(&SCALAR_PERIOD);

        let (_, mut arg1) = arg1.to_bytes_be();

        if size_scalar > arg1.len() {
            let diff = size_scalar - arg1.len();

            let mut new_vec = vec![0; diff];

            new_vec.append(&mut arg1);

            arg1 = new_vec;
        }

        let mut out = blst::blst_p2::default();
        let mut scalar = blst::blst_scalar::default();

        unsafe {
            blst::blst_scalar_from_bendian(
                &mut scalar as *mut _,
                arg1.as_ptr() as *const _,
            );

            blst::blst_p2_mult(
                &mut out as *mut _,
                arg2 as *const _,
                scalar.b.as_ptr() as *const _,
                size_scalar * 8,
            );
        }
        Ok(BlstP2Element { _val: out })
    }

    fn __eq__(&self, other: &BlstP2Element) -> PyResult<bool> {
        let arg1 = &self._val;
        let arg2 = &other._val;
        let is_equal = unsafe { blst::blst_p2_is_equal(arg1, arg2) };
        Ok(is_equal)
    }

    #[classmethod]
    fn hash_to_group(
        _: &Bound<'_, PyType>,
        arg1: Bound<'_, PyBytes>,
        arg2: Bound<'_, PyBytes>,
    ) -> PyResult<BlstP2Element> {
        let dst = arg1.as_bytes();
        let msg = arg2.as_bytes();

        if msg.len() > 255 {
            return Err(Error::HashToCurveDstTooBig.into());
        }

        let mut out = blst::blst_p2::default();
        let aug = [];

        unsafe {
            blst::blst_hash_to_g2(
                &mut out as *mut _,
                dst.as_ptr(),
                dst.len(),
                msg.as_ptr(),
                msg.len(),
                aug.as_ptr(),
                0,
            );
        };

        Ok(BlstP2Element { _val: out} )
    }
    
}

#[pyfunction]
pub fn miller_loop(
    arg1: BlstP1Element,
    arg2: BlstP2Element,
) -> PyResult<BlstFP12Element> {
    let mut out = blst::blst_fp12::default();

    let mut affine1 = blst::blst_p1_affine::default();
    let mut affine2 = blst::blst_p2_affine::default();

    unsafe {
        blst::blst_p1_to_affine(&mut affine1 as *mut _, &arg1._val);
        blst::blst_p2_to_affine(&mut affine2 as *mut _, &arg2._val);

        blst::blst_miller_loop(&mut out as *mut _, &affine2, &affine1);
    }

    Ok(BlstFP12Element { _val: out })
}

#[pymethods]
impl BlstFP12Element {
    #[new]
    fn new() -> Self {
        BlstFP12Element {
            _val: blst::blst_fp12::default(),
        }
    }

    fn __mul__(&self, arg: Self) -> PyResult<Self> {
        let arg1 = &self._val;
        let arg2 = &arg._val;

        let mut out = blst::blst_fp12::default();

        unsafe {
            blst::blst_fp12_mul(&mut out as *mut _, arg1, arg2);
        }
        Ok(BlstFP12Element { _val: out })
    }
}

#[pyfunction]
pub fn final_verify(
    arg1: BlstFP12Element,
    arg2: BlstFP12Element,
) -> PyResult<bool> {
    let verified = unsafe { blst::blst_fp12_finalverify(&arg1._val, &arg2._val) };

    Ok(verified)
}

/// A Python module implemented in Rust.
#[pymodule]
fn pyblst(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<BlstP1Element>()?;
    m.add_class::<BlstP2Element>()?;
    m.add_class::<BlstFP12Element>()?;
    m.add_function(wrap_pyfunction!(miller_loop, m)?)?;
    m.add_function(wrap_pyfunction!(final_verify, m)?)?;
    Ok(())
}
