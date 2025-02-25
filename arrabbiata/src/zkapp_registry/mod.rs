use std::collections::HashMap;

use crate::interpreter::InterpreterEnv;

/// A ZkApp is simply a method taking a mutable interpreter environment and
/// returning nothing
type ZkApp<E> = Box<dyn Fn(&mut E)>;

pub struct Registry<E: InterpreterEnv> {
    apps: HashMap<String, ZkApp<E>>,
}

impl<E: InterpreterEnv> Registry<E> {
    pub fn register(&mut self, name: String, app: Box<dyn Fn(&mut E)>) {
        self.apps.insert(name, app);
    }

    pub fn get(&self, name: String) -> Option<&dyn Fn(&mut E)> {
        let x = self.apps.get(&name);
        match x {
            None => None,
            Some(boxed_fn) => Some(boxed_fn),
        }
    }
}
