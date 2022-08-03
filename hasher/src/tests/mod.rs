use crate::{create_legacy, Hashable, Hasher, ROInput};

mod hasher;

#[test]
fn interfaces() {
    #[derive(Clone)]
    struct Foo {
        x: u32,
        y: u64,
    }

    impl Hashable for Foo {
        type D = u64;

        fn to_roinput(&self) -> ROInput {
            ROInput::new().append_u32(self.x).append_u64(self.y)
        }

        fn domain_string(id: u64) -> Option<String> {
            format!("Foo {}", id).into()
        }
    }

    // Usage 1: incremental interface
    let mut hasher = create_legacy::<Foo>(0);
    hasher.update(&Foo { x: 3, y: 1 });
    let x1 = hasher.digest(); // Resets to previous init state (0)
    hasher.update(&Foo { x: 82, y: 834 });
    hasher.update(&Foo { x: 1235, y: 93 });
    hasher.digest(); // Resets to previous init state (0)
    hasher.init(1);
    hasher.update(&Foo { x: 82, y: 834 });
    let x2 = hasher.digest(); // Resets to previous init state (1)

    // Usage 2: builder interface with one-shot pattern
    let mut hasher = create_legacy::<Foo>(0);
    let y1 = hasher.update(&Foo { x: 3, y: 1 }).digest(); // Resets to previous init state (0)
    hasher.update(&Foo { x: 31, y: 21 }).digest();

    // Usage 3: builder interface with one-shot pattern also setting init state
    let mut hasher = create_legacy::<Foo>(0);
    let y2 = hasher.init(0).update(&Foo { x: 3, y: 1 }).digest(); // Resets to previous init state (1)
    let y3 = hasher.init(1).update(&Foo { x: 82, y: 834 }).digest(); // Resets to previous init state (2)

    // Usage 4: one-shot interfaces
    let mut hasher = create_legacy::<Foo>(0);
    let y4 = hasher.hash(&Foo { x: 3, y: 1 });
    let y5 = hasher.init_and_hash(1, &Foo { x: 82, y: 834 });

    assert_eq!(x1, y1);
    assert_eq!(x1, y2);
    assert_eq!(x2, y3);
    assert_eq!(x1, y4);
    assert_eq!(x2, y5);
    assert_ne!(x1, y5);
    assert_ne!(x2, y4);
    assert_ne!(x1, y3);
    assert_ne!(x2, y2);
}
