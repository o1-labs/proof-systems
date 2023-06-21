use criterion::{
    measurement::{Measurement, ValueFormatter},
    Criterion,
};
use dhat::HeapStats;
use rand::Rng;
use std::ops::Mul;

pub struct MemoryFormater;

pub enum Unit {
    B,
    KB,
    MB,
    GB,
}
impl Unit {
    pub fn factor_and_unit(typical: f64) -> (f64, Self) {
        use Unit::*;
        let (unit, denominator) = match typical as u64 {
            //should decide between powers of ten or two
            // x if x < 1 << 10 => (B, 1),
            // x if x < 1 << 20 => (KB, 1 << 10),
            // x if x < 1 << 30 => (MB, 1 << 20),
            // _ => (GB, 1 << 30),
            x if x < 1 << 10 => (B, 1),
            x if x < 1 << 20 => (KB, 1000),
            x if x < 1 << 30 => (MB, 1000 * 1000),
            _ => (GB, 1000 * 1000 * 1000),
        };
        (1.0 / denominator as f64, unit)
    }
}

impl ValueFormatter for MemoryFormater {
    fn scale_values(&self, typical_value: f64, values: &mut [f64]) -> &'static str {
        let (factor, unit) = Unit::factor_and_unit(typical_value);
        for v in values.iter_mut() {
            *v *= factor;
            assert!(!v.is_nan())
        }
        match unit {
            Unit::B => "B",
            Unit::KB => "KB",
            Unit::MB => "MB",
            Unit::GB => "GB",
        }
    }

    fn scale_throughputs(
        &self,
        typical_value: f64,
        throughput: &criterion::Throughput,
        values: &mut [f64],
    ) -> &'static str {
        let t = match throughput {
            criterion::Throughput::Elements(elems) => (*elems) as f64,
            _ => todo!(),
        };
        let (factor, unit) = Unit::factor_and_unit(typical_value / t);
        for v in values.iter_mut() {
            *v /= t;
            *v *= factor;
            assert_ne!(v, &f64::NAN);
        }
        match unit {
            Unit::B => "B/elem",
            Unit::KB => "KB/elem",
            Unit::MB => "MB/elem",
            Unit::GB => "GB/elem",
        }
    }

    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        "B"
    }
}
#[derive(Default, Debug, Clone, Copy)]
pub struct Bytes(pub usize);
impl Mul<u64> for Bytes {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        Bytes(self.0.checked_mul(rhs as usize).expect("overflowing"))
    }
}

/// A memory measurement for criterion, not a proper implementation, not to be used outside of this benchmark target
#[derive(Default)]
pub struct MaxMemoryUse {
    bytes: Bytes,
}
impl MaxMemoryUse {
    pub fn criterion() -> Criterion<MaxMemoryUse> {
        Criterion::default().with_measurement(MaxMemoryUse { bytes: Bytes(1) })
    }
    pub fn measure_function<F: Fn()>(f: F) -> Self {
        let _profiler = dhat::Profiler::builder().testing().build();
        let before = HeapStats::get();
        f();
        let after = HeapStats::get();
        assert!(after.max_bytes >= before.max_bytes);
        let bytes = Bytes(after.max_bytes);
        Self { bytes }
    }
}

impl Measurement for MaxMemoryUse {
    type Intermediate = Bytes;

    type Value = Bytes;

    fn start(&self) -> Self::Intermediate {
        self.bytes
    }

    fn end(&self, i: Self::Intermediate) -> Self::Value {
        //criterion starts panicking in many cases related the measurement being too precise
        //so we add an small error to each measurement
        let bytes = i;
        let mut rng = rand::thread_rng();
        assert!(bytes.0 > 200);
        let e = rng.gen_range(0..bytes.0) / 200;
        let sign: bool = rng.gen();
        let bytes = if sign { bytes.0 + e } else { bytes.0 - e };

        let bytes = std::cmp::max(bytes, 1);
        Bytes(bytes)
    }

    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        let (Bytes(a), Bytes(b)) = (v1, v2);
        Bytes(a + b)
    }

    fn zero(&self) -> Self::Value {
        Bytes(0)
    }

    fn to_f64(&self, Bytes(val): &Self::Value) -> f64 {
        let v = *val as f64;
        assert!(!v.is_nan());
        if v.is_sign_negative() {
            panic!("to negative {v}");
        }
        v
    }

    fn formatter(&self) -> &dyn criterion::measurement::ValueFormatter {
        &MemoryFormater
    }
}
