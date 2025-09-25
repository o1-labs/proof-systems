use crate::wrappers::field::{WasmPastaFp, WasmPastaFq};
use mina_curves::pasta::{
    curves::{
        pallas::{G_GENERATOR_X as GeneratorPallasX, G_GENERATOR_Y as GeneratorPallasY},
        vesta::{G_GENERATOR_X as GeneratorVestaX, G_GENERATOR_Y as GeneratorVestaY},
    },
    Pallas as AffinePallas, Vesta as AffineVesta,
};
use napi_derive::napi;

#[napi(object)]
#[derive(Clone, Debug)]
pub struct WasmGPallas {
    pub x: WasmPastaFp,
    pub y: WasmPastaFp,
    pub infinity: bool,
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct WasmGVesta {
    pub x: WasmPastaFq,
    pub y: WasmPastaFq,
    pub infinity: bool,
}

impl From<AffinePallas> for WasmGPallas {
    fn from(point: AffinePallas) -> Self {
        Self {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

impl From<&AffinePallas> for WasmGPallas {
    fn from(point: &AffinePallas) -> Self {
        Self {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

impl From<WasmGPallas> for AffinePallas {
    fn from(point: WasmGPallas) -> Self {
        AffinePallas {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

impl From<&WasmGPallas> for AffinePallas {
    fn from(point: &WasmGPallas) -> Self {
        AffinePallas {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

impl From<AffineVesta> for WasmGVesta {
    fn from(point: AffineVesta) -> Self {
        Self {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

impl From<&AffineVesta> for WasmGVesta {
    fn from(point: &AffineVesta) -> Self {
        Self {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

impl From<WasmGVesta> for AffineVesta {
    fn from(point: WasmGVesta) -> Self {
        AffineVesta {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

impl From<&WasmGVesta> for AffineVesta {
    fn from(point: &WasmGVesta) -> Self {
        AffineVesta {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

#[napi]
pub fn caml_pallas_affine_one() -> WasmGPallas {
    WasmGPallas {
        x: WasmPastaFp::from(GeneratorPallasX),
        y: WasmPastaFp::from(GeneratorPallasY),
        infinity: false,
    }
}

#[napi]
pub fn caml_vesta_affine_one() -> WasmGVesta {
    WasmGVesta {
        x: WasmPastaFq::from(GeneratorVestaX),
        y: WasmPastaFq::from(GeneratorVestaY),
        infinity: false,
    }
}
