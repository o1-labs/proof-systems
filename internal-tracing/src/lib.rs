use std::time::SystemTime;

#[cfg(feature = "enabled")]
pub use serde_json::{json, to_writer as json_to_writer, Value as JsonValue};

pub fn time_to_micros(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

pub fn now_micros() -> u64 {
    time_to_micros(SystemTime::now())
}

pub enum TimeInput {
    Microseconds(u64),
    SystemTime(SystemTime),
}

impl TimeInput {
    pub fn micros(self) -> u64 {
        match self {
            Self::Microseconds(v) => v,
            Self::SystemTime(v) => time_to_micros(v),
        }
    }
}

impl From<u64> for TimeInput {
    fn from(value: u64) -> Self {
        Self::Microseconds(value)
    }
}

impl From<SystemTime> for TimeInput {
    fn from(value: SystemTime) -> Self {
        Self::SystemTime(value)
    }
}

/// Declare traces group.
///
/// Creates a module with the passed `$name`.
///
/// **Note:**Traces are stored locally for each thread (`thread_local`).
///
/// Module exposes two main methods:
/// - `fn start_tracing()` - Simply calls `take_traces()` and discards
///   the result, in order to clean up old traces.
/// - `fn take_traces()` - Take accumulated traces.
#[cfg(feature = "enabled")]
#[macro_export]
macro_rules! decl_traces {
    ($name:ident; $($checkpoint:ident),+) => {

        pub mod $name {
            use std::rc::Rc;
            use std::cell::RefCell;

            #[derive(serde::Serialize, Debug, Default, Clone)]
            pub struct Traces {
                $(
                pub $checkpoint: (u64, $crate::JsonValue),
                )*
            }

            impl std::fmt::Display for Traces {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    let mut arr = [
                        $(
                        (stringify!($checkpoint), self.$checkpoint.0, &self.$checkpoint.1),
                        )+
                    ];
                    arr.sort_by_key(|v| v.1);
                    let mut buf = Vec::new();
                    for (name, time, meta) in arr.into_iter().filter(|v| v.1 != 0) {
                        $crate::json_to_writer(&mut buf, &(name, (time as f64) / 1_000_000.0)).unwrap();
                        buf.push(b'\n');
                        if !meta.is_null() {
                            $crate::json_to_writer(&mut buf, meta).unwrap();
                            buf.push(b'\n');
                        }
                    }
                    write!(f, "{}", &String::from_utf8(buf).unwrap())
                }
            }

            impl From<Traces> for String {
                fn from(t: Traces) -> Self {
                    t.to_string()
                }
            }

            thread_local! {
                pub static TRACES: Rc<RefCell<Traces>> = Default::default();
            }

            /// Clean up old traces and start fresh.
            pub fn start_tracing() {
                take_traces();
            }

            /// Take captured traces.
            pub fn take_traces() -> Traces {
                TRACES.with(|v| v.take())
            }

            #[cfg(feature = "ocaml_types")]
            #[allow(non_local_definitions)]
            #[allow(dead_code)]
            pub mod caml {
                use super::*;

                #[derive(Debug, ocaml::IntoValue, ocaml::FromValue, ocaml_gen::Struct)]
                pub struct CamlTraces(String);

                impl From<Traces> for CamlTraces {
                    fn from(t: Traces) -> Self {
                        Self(t.to_string())
                    }
                }
            }
        }
    };
}
/// Noop. Internal tracing not enabled!
#[cfg(not(feature = "enabled"))]
#[macro_export]
macro_rules! decl_traces {
    ($($_ignored:tt)+) => {};
}

/// Capture the trace/checkpoint.
#[cfg(feature = "enabled")]
#[macro_export]
macro_rules! checkpoint {
    ($name:ident; $checkpoint:ident) => {
        $crate::checkpoint!(|$name; $checkpoint, $crate::now_micros(), $crate::json!(null));
    };
    ($name:ident; $checkpoint:ident, {$($metadata:tt)+}) => {
        $crate::checkpoint!(|$name; $checkpoint, $crate::now_micros(), $crate::json!({$($metadata)+}));
    };
    ($name:ident; $checkpoint:ident, $time:expr) => {
        $crate::checkpoint!(|$name; $checkpoint, $crate::TimeInput::from($time).micros(), $crate::json!(null));
    };
    ($name:ident; $checkpoint:ident, $time:expr, {$($metadata:tt)+}) => {
        $crate::checkpoint!(|$name; $checkpoint, $crate::TimeInput::from($time).micros(), $crate::json!({$($metadata)+}));
    };
    (|$name:ident; $checkpoint:ident, $time:expr, $metadata:expr) => {
        $name::TRACES.with(|traces| traces.borrow_mut().$checkpoint = ($time, $metadata));
    };
}
/// Noop. Internal tracing not enabled!
#[cfg(not(feature = "enabled"))]
#[macro_export]
macro_rules! checkpoint {
    ($($_ignored:tt)+) => {};
}

#[cfg(feature = "enabled")]
#[cfg(test)]
mod tests {
    use super::*;

    decl_traces!(test_fn; c1, c2, c3, c4);

    #[test]
    fn test_fn() {
        test_fn::start_tracing();

        checkpoint!(test_fn; c1);
        checkpoint!(test_fn; c2, 2);
        checkpoint!(test_fn; c3, { "arg": 1 });
        checkpoint!(test_fn; c4, 3, { "arg": 2 });

        let traces = test_fn::take_traces();

        assert_ne!(traces.c1.0, 0);
        assert_eq!(traces.c1.1, serde_json::Value::Null);

        assert_eq!(traces.c2.0, 2);
        assert_eq!(traces.c2.1, serde_json::Value::Null);

        assert_ne!(traces.c3.0, 0);
        assert_eq!(traces.c3.1, serde_json::json!({ "arg": 1 }));

        assert_eq!(traces.c4.0, 3);
        assert_eq!(traces.c4.1, serde_json::json!({ "arg": 2 }));
    }
}
