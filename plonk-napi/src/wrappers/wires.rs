use kimchi::circuits::wires::Wire;
use napi_derive::napi;

#[napi(object)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NapiWire {
    pub row: u32,
    pub col: u32,
}

impl From<NapiWire> for Wire {
    fn from(value: NapiWire) -> Self {
        Wire {
            row: value.row as usize,
            col: value.col as usize,
        }
    }
}

impl From<Wire> for NapiWire {
    fn from(value: Wire) -> Self {
        Self {
            row: value.row as u32,
            col: value.col as u32,
        }
    }
}
