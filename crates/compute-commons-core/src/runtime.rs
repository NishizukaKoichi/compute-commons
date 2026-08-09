use wasmtime::{Config, Engine, Linker, Module, Store};

use crate::{CommonsError, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionOutcome {
    pub output: i32,
    pub module_imports: usize,
}

pub struct WasmRuntime {
    engine: Engine,
}

impl WasmRuntime {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(runtime_error)?;
        Ok(Self { engine })
    }

    pub fn execute(
        &self,
        module: &[u8],
        entrypoint: &str,
        input: i32,
        fuel: u64,
    ) -> Result<ExecutionOutcome> {
        let module = Module::new(&self.engine, module).map_err(runtime_error)?;
        if module.imports().len() != 0 {
            return Err(CommonsError::Unsupported);
        }
        let linker = Linker::<()>::new(&self.engine);
        let mut store = Store::new(&self.engine, ());
        store.set_fuel(fuel).map_err(runtime_error)?;
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(runtime_error)?;
        let function = instance
            .get_typed_func::<i32, i32>(&mut store, entrypoint)
            .map_err(runtime_error)?;
        let output = function.call(&mut store, input).map_err(runtime_error)?;
        Ok(ExecutionOutcome {
            output,
            module_imports: 0,
        })
    }
}

fn runtime_error(error: impl std::fmt::Display) -> CommonsError {
    CommonsError::Runtime(error.to_string())
}
