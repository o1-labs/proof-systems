use crate::wrappers::field::{NapiPastaFp, NapiPastaFq};
use mina_curves::pasta::{
    curves::{
        pallas::{G_GENERATOR_X as GeneratorPallasX, G_GENERATOR_Y as GeneratorPallasY},
        vesta::{G_GENERATOR_X as GeneratorVestaX, G_GENERATOR_Y as GeneratorVestaY},
    },
    Pallas as AffinePallas, Vesta as AffineVesta,
};
use napi_derive::napi;
use serde::{Deserialize, Serialize};

#[napi(object)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NapiGPallas {
    pub x: NapiPastaFp,
    pub y: NapiPastaFp,
    pub infinity: bool,
}

#[napi(object)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NapiGVesta {
    pub x: NapiPastaFq,
    pub y: NapiPastaFq,
    pub infinity: bool,
}

impl From<AffinePallas> for NapiGPallas {
    fn from(point: AffinePallas) -> Self {
        Self {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

impl From<&AffinePallas> for NapiGPallas {
    fn from(point: &AffinePallas) -> Self {
        Self {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

impl From<NapiGPallas> for AffinePallas {
    fn from(point: NapiGPallas) -> Self {
        AffinePallas {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

impl From<&NapiGPallas> for AffinePallas {
    fn from(point: &NapiGPallas) -> Self {
        AffinePallas {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

impl From<AffineVesta> for NapiGVesta {
    fn from(point: AffineVesta) -> Self {
        Self {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

impl From<&AffineVesta> for NapiGVesta {
    fn from(point: &AffineVesta) -> Self {
        Self {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

impl From<NapiGVesta> for AffineVesta {
    fn from(point: NapiGVesta) -> Self {
        AffineVesta {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

impl From<&NapiGVesta> for AffineVesta {
    fn from(point: &NapiGVesta) -> Self {
        AffineVesta {
            x: point.x.into(),
            y: point.y.into(),
            infinity: point.infinity,
        }
    }
}

#[napi]
pub fn caml_pallas_affine_one() -> NapiGPallas {
    NapiGPallas {
        x: NapiPastaFp::from(GeneratorPallasX),
        y: NapiPastaFp::from(GeneratorPallasY),
        infinity: false,
    }
}

#[napi]
pub fn caml_vesta_affine_one() -> NapiGVesta {
    NapiGVesta {
        x: NapiPastaFq::from(GeneratorVestaX),
        y: NapiPastaFq::from(GeneratorVestaY),
        infinity: false,
    }
}
