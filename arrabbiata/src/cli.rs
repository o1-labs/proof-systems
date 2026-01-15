use clap::Parser;

use crate::registry::CircuitList;

#[derive(Parser)]
pub struct ExecuteArgs {
    #[arg(
        long = "circuit",
        value_name = "CIRCUIT",
        help = "The circuit to execute (use --list-circuits to see available circuits)",
        default_value = "squaring"
    )]
    pub circuit: String,

    #[arg(
        long,
        short = 'n',
        value_name = "N",
        help = "Number of iterations",
        required_unless_present = "list_circuits"
    )]
    pub n: Option<u64>,

    #[arg(
        long = "srs-size",
        value_name = "SRS_SIZE",
        help = "The SRS size, given in log2",
        required_unless_present = "list_circuits"
    )]
    pub srs_size: Option<usize>,

    #[arg(long = "list-circuits", help = "List all available circuits")]
    pub list_circuits: bool,
}

impl ExecuteArgs {
    /// Validate that the circuit name is registered.
    pub fn validate_circuit<R: CircuitList>(&self, registry: &R) -> Result<(), String> {
        if !registry.contains(&self.circuit) {
            let available: Vec<&str> = registry.names();
            return Err(format!(
                "Unknown circuit '{}'. Available circuits: {}",
                self.circuit,
                available.join(", ")
            ));
        }
        Ok(())
    }
}

#[derive(Parser)]
#[command(
    name = "arrabbiata",
    version = "0.1",
    about = "Arrabbiata - a generic recursive SNARK based on folding schemes"
)]
pub enum Commands {
    #[command(name = "execute")]
    Execute(ExecuteArgs),
}
