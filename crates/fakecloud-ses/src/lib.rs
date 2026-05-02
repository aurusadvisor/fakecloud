pub mod dkim;
pub mod fanout;
pub mod mime;
pub(crate) mod service;
pub mod state;
pub mod v1;

pub use service::SesV2Service;
pub use state::{
    ConfigurationSet, ContactList, DedicatedIpPool, EmailIdentity, EmailTemplate, EventDestination,
    IpFilter, ReceiptAction, ReceiptFilter, ReceiptRule, ReceiptRuleSet, SentEmail, SesSnapshot,
    SesState, SharedSesState, SES_SNAPSHOT_SCHEMA_VERSION,
};
