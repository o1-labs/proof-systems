use kimchi::circuits::wires::Wire as KimchiWire;
use napi_derive::napi;

#[napi(object)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NapiWire {
    pub row: u32,
    pub col: u32,
}

impl From<NapiWire> for KimchiWire {
    fn from(value: NapiWire) -> Self {
        KimchiWire {
            row: value.row as usize,
            col: value.col as usize,
        }
    }
}

impl From<KimchiWire> for NapiWire {
    fn from(value: KimchiWire) -> Self {
        Self {
            row: value.row as u32,
            col: value.col as u32,
        }
    }
}
