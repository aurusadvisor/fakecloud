pub mod fanout;
pub mod mime;
pub(crate) mod service;
pub(crate) mod state;
pub mod v1;

pub use service::SesV2Service;
pub use state::{
    ReceiptAction, SentEmail, SesSnapshot, SharedSesState, SES_SNAPSHOT_SCHEMA_VERSION,
};
