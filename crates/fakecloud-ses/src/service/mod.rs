mod account;
mod configuration_sets;
mod contact_lists;
mod identities;
mod misc;
mod sending;
mod suppression;
mod templates;

use async_trait::async_trait;
use http::{Method, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};
use fakecloud_persistence::SnapshotStore;

use crate::fanout::SesDeliveryContext;
use crate::state::{
    EventDestination, SesSnapshot, SharedSesState, Topic, TopicPreference,
    SES_SNAPSHOT_SCHEMA_VERSION,
};

pub struct SesV2Service {
    state: SharedSesState,
    delivery_ctx: Option<SesDeliveryContext>,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
}

impl SesV2Service {
    pub fn new(state: SharedSesState) -> Self {
        Self {
            state,
            delivery_ctx: None,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    /// Attach a delivery context for cross-service event fanout.
    pub fn with_delivery(mut self, ctx: SesDeliveryContext) -> Self {
        self.delivery_ctx = Some(ctx);
        self
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
    }

    /// Persist current state as a snapshot. Held across the
    /// clone-serialize-write sequence to prevent stale-last writes,
    /// with serde + file I/O offloaded to the blocking pool.
    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = SesSnapshot {
            schema_version: SES_SNAPSHOT_SCHEMA_VERSION,
            accounts: Some(self.state.read().clone()),
            state: None,
        };
        let join = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let bytes = serde_json::to_vec(&snapshot)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            store.save(&bytes)
        })
        .await;
        match join {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(%err, "failed to write ses snapshot"),
            Err(err) => tracing::error!(%err, "ses snapshot task panicked"),
        }
    }

    /// Determine the action from the HTTP method and path segments.
    /// SES v2 uses REST-style routing with base path /v2/email/:
    ///   GET    /v2/email/account                         -> GetAccount
    ///   POST   /v2/email/identities                      -> CreateEmailIdentity
    ///   GET    /v2/email/identities                      -> ListEmailIdentities
    ///   GET    /v2/email/identities/{id}                 -> GetEmailIdentity
    ///   DELETE /v2/email/identities/{id}                 -> DeleteEmailIdentity
    ///   POST   /v2/email/configuration-sets              -> CreateConfigurationSet
    ///   GET    /v2/email/configuration-sets              -> ListConfigurationSets
    ///   GET    /v2/email/configuration-sets/{name}       -> GetConfigurationSet
    ///   DELETE /v2/email/configuration-sets/{name}       -> DeleteConfigurationSet
    ///   POST   /v2/email/templates                       -> CreateEmailTemplate
    ///   GET    /v2/email/templates                       -> ListEmailTemplates
    ///   GET    /v2/email/templates/{name}                -> GetEmailTemplate
    ///   PUT    /v2/email/templates/{name}                -> UpdateEmailTemplate
    ///   DELETE /v2/email/templates/{name}                -> DeleteEmailTemplate
    ///   POST   /v2/email/outbound-emails                 -> SendEmail
    ///   POST   /v2/email/outbound-bulk-emails            -> SendBulkEmail
    ///   POST   /v2/email/tags                            -> TagResource
    ///   DELETE /v2/email/tags                            -> UntagResource
    ///   GET    /v2/email/tags                            -> ListTagsForResource
    ///   POST   /v2/email/contact-lists                   -> CreateContactList
    ///   GET    /v2/email/contact-lists                   -> ListContactLists
    ///   GET    /v2/email/contact-lists/{name}            -> GetContactList
    ///   PUT    /v2/email/contact-lists/{name}            -> UpdateContactList
    ///   DELETE /v2/email/contact-lists/{name}            -> DeleteContactList
    ///   POST   /v2/email/contact-lists/{name}/contacts   -> CreateContact
    ///   GET    /v2/email/contact-lists/{name}/contacts   -> ListContacts
    ///   GET    /v2/email/contact-lists/{name}/contacts/{email} -> GetContact
    ///   PUT    /v2/email/contact-lists/{name}/contacts/{email} -> UpdateContact
    ///   DELETE /v2/email/contact-lists/{name}/contacts/{email} -> DeleteContact
    ///   PUT    /v2/email/suppression/addresses            -> PutSuppressedDestination
    ///   GET    /v2/email/suppression/addresses            -> ListSuppressedDestinations
    ///   GET    /v2/email/suppression/addresses/{email}    -> GetSuppressedDestination
    ///   DELETE /v2/email/suppression/addresses/{email}    -> DeleteSuppressedDestination
    ///   POST   /v2/email/configuration-sets/{name}/event-destinations -> CreateConfigurationSetEventDestination
    ///   GET    /v2/email/configuration-sets/{name}/event-destinations -> GetConfigurationSetEventDestinations
    ///   PUT    /v2/email/configuration-sets/{name}/event-destinations/{dest} -> UpdateConfigurationSetEventDestination
    ///   DELETE /v2/email/configuration-sets/{name}/event-destinations/{dest} -> DeleteConfigurationSetEventDestination
    ///   POST   /v2/email/identities/{id}/policies/{policy} -> CreateEmailIdentityPolicy
    ///   GET    /v2/email/identities/{id}/policies         -> GetEmailIdentityPolicies
    ///   PUT    /v2/email/identities/{id}/policies/{policy} -> UpdateEmailIdentityPolicy
    ///   DELETE /v2/email/identities/{id}/policies/{policy} -> DeleteEmailIdentityPolicy
    ///   PUT    /v2/email/identities/{id}/dkim              -> PutEmailIdentityDkimAttributes
    ///   PUT    /v2/email/identities/{id}/dkim/signing      -> PutEmailIdentityDkimSigningAttributes
    ///   PUT    /v2/email/identities/{id}/feedback          -> PutEmailIdentityFeedbackAttributes
    ///   PUT    /v2/email/identities/{id}/mail-from         -> PutEmailIdentityMailFromAttributes
    ///   PUT    /v2/email/identities/{id}/configuration-set -> PutEmailIdentityConfigurationSetAttributes
    ///   PUT    /v2/email/configuration-sets/{name}/sending             -> PutConfigurationSetSendingOptions
    ///   PUT    /v2/email/configuration-sets/{name}/delivery-options    -> PutConfigurationSetDeliveryOptions
    ///   PUT    /v2/email/configuration-sets/{name}/tracking-options    -> PutConfigurationSetTrackingOptions
    ///   PUT    /v2/email/configuration-sets/{name}/suppression-options -> PutConfigurationSetSuppressionOptions
    ///   PUT    /v2/email/configuration-sets/{name}/reputation-options  -> PutConfigurationSetReputationOptions
    ///   PUT    /v2/email/configuration-sets/{name}/vdm-options         -> PutConfigurationSetVdmOptions
    ///   PUT    /v2/email/configuration-sets/{name}/archiving-options   -> PutConfigurationSetArchivingOptions
    ///   POST   /v2/email/custom-verification-email-templates           -> CreateCustomVerificationEmailTemplate
    ///   GET    /v2/email/custom-verification-email-templates            -> ListCustomVerificationEmailTemplates
    ///   GET    /v2/email/custom-verification-email-templates/{name}     -> GetCustomVerificationEmailTemplate
    ///   PUT    /v2/email/custom-verification-email-templates/{name}     -> UpdateCustomVerificationEmailTemplate
    ///   DELETE /v2/email/custom-verification-email-templates/{name}     -> DeleteCustomVerificationEmailTemplate
    ///   POST   /v2/email/outbound-custom-verification-emails            -> SendCustomVerificationEmail
    ///   POST   /v2/email/templates/{name}/render                        -> TestRenderEmailTemplate
    ///   POST   /v2/email/import-jobs                                     -> CreateImportJob
    ///   POST   /v2/email/import-jobs/list                                -> ListImportJobs
    ///   GET    /v2/email/import-jobs/{id}                                -> GetImportJob
    ///   POST   /v2/email/export-jobs                                     -> CreateExportJob
    ///   POST   /v2/email/list-export-jobs                                -> ListExportJobs
    ///   PUT    /v2/email/export-jobs/{id}/cancel                         -> CancelExportJob
    ///   GET    /v2/email/export-jobs/{id}                                -> GetExportJob
    ///   POST   /v2/email/tenants                                         -> CreateTenant
    ///   POST   /v2/email/tenants/list                                    -> ListTenants
    ///   POST   /v2/email/tenants/get                                     -> GetTenant
    ///   POST   /v2/email/tenants/delete                                  -> DeleteTenant
    ///   POST   /v2/email/tenants/resources                               -> CreateTenantResourceAssociation
    ///   POST   /v2/email/tenants/resources/delete                        -> DeleteTenantResourceAssociation
    ///   POST   /v2/email/tenants/resources/list                          -> ListTenantResources
    ///   POST   /v2/email/resources/tenants/list                          -> ListResourceTenants
    ///   POST   /v2/email/reputation/entities                             -> ListReputationEntities
    ///   PUT    /v2/email/reputation/entities/{type}/{ref}/customer-managed-status -> UpdateReputationEntityCustomerManagedStatus
    ///   PUT    /v2/email/reputation/entities/{type}/{ref}/policy          -> UpdateReputationEntityPolicy
    ///   GET    /v2/email/reputation/entities/{type}/{ref}                 -> GetReputationEntity
    ///   POST   /v2/email/metrics/batch                                   -> BatchGetMetricData
    fn resolve_action(req: &AwsRequest) -> Option<(&'static str, Option<String>, Option<String>)> {
        let segs = &req.path_segments;

        if segs.len() < 3 || segs[0] != "v2" || segs[1] != "email" {
            return None;
        }

        let method = &req.method;
        let resource = segs.get(3).map(|s| decode_segment(s));
        let collection = segs[2].as_str();

        match collection {
            "account" => resolve_account_action(method, segs),
            "identities" => resolve_identities_action(method, segs, resource),
            "configuration-sets" => resolve_configuration_sets_action(method, segs, resource),
            "templates" => resolve_templates_action(method, segs, resource),
            "contact-lists" => resolve_contact_lists_action(method, segs, resource),
            "suppression" => resolve_suppression_action(method, segs),
            "tags" if segs.len() == 3 => match *method {
                Method::POST => Some(("TagResource", None, None)),
                Method::DELETE => Some(("UntagResource", None, None)),
                Method::GET => Some(("ListTagsForResource", None, None)),
                _ => None,
            },
            "outbound-emails" if segs.len() == 3 && *method == Method::POST => {
                Some(("SendEmail", None, None))
            }
            "outbound-bulk-emails" if segs.len() == 3 && *method == Method::POST => {
                Some(("SendBulkEmail", None, None))
            }
            "outbound-custom-verification-emails" if segs.len() == 3 && *method == Method::POST => {
                Some(("SendCustomVerificationEmail", None, None))
            }
            "custom-verification-email-templates" => {
                resolve_custom_verification_template_action(method, segs, resource)
            }
            "dedicated-ip-pools" => resolve_dedicated_ip_pools_action(method, segs, resource),
            "dedicated-ips" => resolve_dedicated_ips_action(method, segs, resource),
            "multi-region-endpoints" => {
                resolve_multi_region_endpoints_action(method, segs, resource)
            }
            "import-jobs" => resolve_import_jobs_action(method, segs, resource),
            "export-jobs" => resolve_export_jobs_action(method, segs, resource),
            "list-export-jobs" if segs.len() == 3 && *method == Method::POST => {
                Some(("ListExportJobs", None, None))
            }
            "tenants" => resolve_tenants_action(method, segs),
            "resources" => resolve_resources_action(method, segs),
            "reputation" => resolve_reputation_action(method, segs),
            "metrics" if segs.len() == 4 && segs[3] == "batch" && *method == Method::POST => {
                Some(("BatchGetMetricData", None, None))
            }
            "deliverability-dashboard" => resolve_deliverability_dashboard_action(method, segs),
            "email-address-insights" if segs.len() == 3 && *method == Method::POST => {
                Some(("GetEmailAddressInsights", None, None))
            }
            "insights" if segs.len() == 4 && *method == Method::GET => {
                Some(("GetMessageInsights", resource, None))
            }
            "vdm" if segs.len() == 4 && segs[3] == "recommendations" && *method == Method::POST => {
                Some(("ListRecommendations", None, None))
            }
            _ => None,
        }
    }

    fn parse_body(req: &AwsRequest) -> Result<Value, AwsServiceError> {
        serde_json::from_slice(&req.body).map_err(|_| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Invalid JSON in request body",
            )
        })
    }

    fn json_error(status: StatusCode, code: &str, message: &str) -> AwsResponse {
        let body = json!({
            "__type": code,
            "message": message,
        });
        AwsResponse::json(status, body.to_string())
    }
}

/// URL-decode a path segment (e.g. `test%40example.com` -> `test@example.com`).
fn decode_segment(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

type ResolvedAction = Option<(&'static str, Option<String>, Option<String>)>;

fn resolve_account_action(method: &Method, segs: &[String]) -> ResolvedAction {
    match (method, segs.len()) {
        (&Method::GET, 3) => Some(("GetAccount", None, None)),
        (&Method::POST, 4) if segs[3] == "details" => Some(("PutAccountDetails", None, None)),
        (&Method::PUT, 4) if segs[3] == "sending" => {
            Some(("PutAccountSendingAttributes", None, None))
        }
        (&Method::PUT, 4) if segs[3] == "suppression" => {
            Some(("PutAccountSuppressionAttributes", None, None))
        }
        (&Method::PUT, 4) if segs[3] == "vdm" => Some(("PutAccountVdmAttributes", None, None)),
        (&Method::PUT, 5) if segs[3] == "dedicated-ips" && segs[4] == "warmup" => {
            Some(("PutAccountDedicatedIpWarmupAttributes", None, None))
        }
        _ => None,
    }
}

fn resolve_identities_action(
    method: &Method,
    segs: &[String],
    resource: Option<String>,
) -> ResolvedAction {
    match (method, segs.len()) {
        (&Method::POST, 3) => Some(("CreateEmailIdentity", None, None)),
        (&Method::GET, 3) => Some(("ListEmailIdentities", None, None)),
        (&Method::GET, 4) => Some(("GetEmailIdentity", resource, None)),
        (&Method::DELETE, 4) => Some(("DeleteEmailIdentity", resource, None)),
        (&Method::PUT, 5) if segs[4] == "dkim" => {
            Some(("PutEmailIdentityDkimAttributes", resource, None))
        }
        (&Method::PUT, 5) if segs[4] == "feedback" => {
            Some(("PutEmailIdentityFeedbackAttributes", resource, None))
        }
        (&Method::PUT, 5) if segs[4] == "mail-from" => {
            Some(("PutEmailIdentityMailFromAttributes", resource, None))
        }
        (&Method::PUT, 5) if segs[4] == "configuration-set" => {
            Some(("PutEmailIdentityConfigurationSetAttributes", resource, None))
        }
        (&Method::GET, 5) if segs[4] == "policies" => {
            Some(("GetEmailIdentityPolicies", resource, None))
        }
        (&Method::PUT, 6) if segs[4] == "dkim" && segs[5] == "signing" => {
            Some(("PutEmailIdentityDkimSigningAttributes", resource, None))
        }
        (&Method::POST, 6) if segs[4] == "policies" => Some((
            "CreateEmailIdentityPolicy",
            resource,
            Some(decode_segment(&segs[5])),
        )),
        (&Method::PUT, 6) if segs[4] == "policies" => Some((
            "UpdateEmailIdentityPolicy",
            resource,
            Some(decode_segment(&segs[5])),
        )),
        (&Method::DELETE, 6) if segs[4] == "policies" => Some((
            "DeleteEmailIdentityPolicy",
            resource,
            Some(decode_segment(&segs[5])),
        )),
        _ => None,
    }
}

fn resolve_configuration_sets_action(
    method: &Method,
    segs: &[String],
    resource: Option<String>,
) -> ResolvedAction {
    match (method, segs.len()) {
        (&Method::POST, 3) => Some(("CreateConfigurationSet", None, None)),
        (&Method::GET, 3) => Some(("ListConfigurationSets", None, None)),
        (&Method::GET, 4) => Some(("GetConfigurationSet", resource, None)),
        (&Method::DELETE, 4) => Some(("DeleteConfigurationSet", resource, None)),
        (&Method::POST, 5) if segs[4] == "event-destinations" => {
            Some(("CreateConfigurationSetEventDestination", resource, None))
        }
        (&Method::GET, 5) if segs[4] == "event-destinations" => {
            Some(("GetConfigurationSetEventDestinations", resource, None))
        }
        (&Method::PUT, 5) if segs[4] == "sending" => {
            Some(("PutConfigurationSetSendingOptions", resource, None))
        }
        (&Method::PUT, 5) if segs[4] == "delivery-options" => {
            Some(("PutConfigurationSetDeliveryOptions", resource, None))
        }
        (&Method::PUT, 5) if segs[4] == "tracking-options" => {
            Some(("PutConfigurationSetTrackingOptions", resource, None))
        }
        (&Method::PUT, 5) if segs[4] == "suppression-options" => {
            Some(("PutConfigurationSetSuppressionOptions", resource, None))
        }
        (&Method::PUT, 5) if segs[4] == "reputation-options" => {
            Some(("PutConfigurationSetReputationOptions", resource, None))
        }
        (&Method::PUT, 5) if segs[4] == "vdm-options" => {
            Some(("PutConfigurationSetVdmOptions", resource, None))
        }
        (&Method::PUT, 5) if segs[4] == "archiving-options" => {
            Some(("PutConfigurationSetArchivingOptions", resource, None))
        }
        (&Method::PUT, 6) if segs[4] == "event-destinations" => Some((
            "UpdateConfigurationSetEventDestination",
            resource,
            Some(decode_segment(&segs[5])),
        )),
        (&Method::DELETE, 6) if segs[4] == "event-destinations" => Some((
            "DeleteConfigurationSetEventDestination",
            resource,
            Some(decode_segment(&segs[5])),
        )),
        _ => None,
    }
}

fn resolve_templates_action(
    method: &Method,
    segs: &[String],
    resource: Option<String>,
) -> ResolvedAction {
    match (method, segs.len()) {
        (&Method::POST, 3) => Some(("CreateEmailTemplate", None, None)),
        (&Method::GET, 3) => Some(("ListEmailTemplates", None, None)),
        (&Method::GET, 4) => Some(("GetEmailTemplate", resource, None)),
        (&Method::PUT, 4) => Some(("UpdateEmailTemplate", resource, None)),
        (&Method::DELETE, 4) => Some(("DeleteEmailTemplate", resource, None)),
        (&Method::POST, 5) if segs[4] == "render" => {
            Some(("TestRenderEmailTemplate", resource, None))
        }
        _ => None,
    }
}

fn resolve_contact_lists_action(
    method: &Method,
    segs: &[String],
    resource: Option<String>,
) -> ResolvedAction {
    match (method, segs.len()) {
        (&Method::POST, 3) => Some(("CreateContactList", None, None)),
        (&Method::GET, 3) => Some(("ListContactLists", None, None)),
        (&Method::GET, 4) => Some(("GetContactList", resource, None)),
        (&Method::PUT, 4) => Some(("UpdateContactList", resource, None)),
        (&Method::DELETE, 4) => Some(("DeleteContactList", resource, None)),
        (&Method::POST, 5) if segs[4] == "contacts" => Some(("CreateContact", resource, None)),
        (&Method::GET, 5) if segs[4] == "contacts" => Some(("ListContacts", resource, None)),
        // SDK sends POST .../contacts/list for ListContacts
        (&Method::POST, 6) if segs[4] == "contacts" && segs[5] == "list" => {
            Some(("ListContacts", resource, None))
        }
        (&Method::GET, 6) if segs[4] == "contacts" => {
            Some(("GetContact", resource, Some(decode_segment(&segs[5]))))
        }
        (&Method::PUT, 6) if segs[4] == "contacts" => {
            Some(("UpdateContact", resource, Some(decode_segment(&segs[5]))))
        }
        (&Method::DELETE, 6) if segs[4] == "contacts" => {
            Some(("DeleteContact", resource, Some(decode_segment(&segs[5]))))
        }
        _ => None,
    }
}

fn resolve_suppression_action(method: &Method, segs: &[String]) -> ResolvedAction {
    if segs.get(3).map(|s| s.as_str()) != Some("addresses") {
        return None;
    }
    match (method, segs.len()) {
        (&Method::PUT, 4) => Some(("PutSuppressedDestination", None, None)),
        (&Method::GET, 4) => Some(("ListSuppressedDestinations", None, None)),
        (&Method::GET, 5) => Some((
            "GetSuppressedDestination",
            Some(decode_segment(&segs[4])),
            None,
        )),
        (&Method::DELETE, 5) => Some((
            "DeleteSuppressedDestination",
            Some(decode_segment(&segs[4])),
            None,
        )),
        _ => None,
    }
}

fn resolve_custom_verification_template_action(
    method: &Method,
    segs: &[String],
    resource: Option<String>,
) -> ResolvedAction {
    match (method, segs.len()) {
        (&Method::POST, 3) => Some(("CreateCustomVerificationEmailTemplate", None, None)),
        (&Method::GET, 3) => Some(("ListCustomVerificationEmailTemplates", None, None)),
        (&Method::GET, 4) => Some(("GetCustomVerificationEmailTemplate", resource, None)),
        (&Method::PUT, 4) => Some(("UpdateCustomVerificationEmailTemplate", resource, None)),
        (&Method::DELETE, 4) => Some(("DeleteCustomVerificationEmailTemplate", resource, None)),
        _ => None,
    }
}

fn resolve_deliverability_dashboard_action(method: &Method, segs: &[String]) -> ResolvedAction {
    match (method, segs.len()) {
        (&Method::GET, 3) => Some(("GetDeliverabilityDashboardOptions", None, None)),
        (&Method::PUT, 3) => Some(("PutDeliverabilityDashboardOption", None, None)),
        (&Method::POST, 4) if segs[3] == "test" => {
            Some(("CreateDeliverabilityTestReport", None, None))
        }
        (&Method::GET, 4) if segs[3] == "blacklist-report" => {
            Some(("GetBlacklistReports", None, None))
        }
        (&Method::GET, 4) if segs[3] == "test-reports" => {
            Some(("ListDeliverabilityTestReports", None, None))
        }
        (&Method::GET, 5) if segs[3] == "test-reports" => Some((
            "GetDeliverabilityTestReport",
            Some(decode_segment(&segs[4])),
            None,
        )),
        (&Method::GET, 5) if segs[3] == "campaigns" => Some((
            "GetDomainDeliverabilityCampaign",
            Some(decode_segment(&segs[4])),
            None,
        )),
        (&Method::GET, 5) if segs[3] == "statistics-report" => Some((
            "GetDomainStatisticsReport",
            Some(decode_segment(&segs[4])),
            None,
        )),
        (&Method::GET, 6) if segs[3] == "domains" && segs[5] == "campaigns" => Some((
            "ListDomainDeliverabilityCampaigns",
            Some(decode_segment(&segs[4])),
            None,
        )),
        _ => None,
    }
}

fn resolve_dedicated_ip_pools_action(
    method: &Method,
    segs: &[String],
    resource: Option<String>,
) -> ResolvedAction {
    match (method, segs.len()) {
        (&Method::POST, 3) => Some(("CreateDedicatedIpPool", None, None)),
        (&Method::GET, 3) => Some(("ListDedicatedIpPools", None, None)),
        (&Method::GET, 4) => Some(("GetDedicatedIpPool", resource, None)),
        (&Method::DELETE, 4) => Some(("DeleteDedicatedIpPool", resource, None)),
        (&Method::PUT, 5) if segs[4] == "scaling" => {
            Some(("PutDedicatedIpPoolScalingAttributes", resource, None))
        }
        _ => None,
    }
}

fn resolve_dedicated_ips_action(
    method: &Method,
    segs: &[String],
    resource: Option<String>,
) -> ResolvedAction {
    match (method, segs.len()) {
        (&Method::GET, 3) => Some(("GetDedicatedIps", None, None)),
        (&Method::GET, 4) => Some(("GetDedicatedIp", resource, None)),
        (&Method::PUT, 5) if segs[4] == "pool" => Some(("PutDedicatedIpInPool", resource, None)),
        (&Method::PUT, 5) if segs[4] == "warmup" => {
            Some(("PutDedicatedIpWarmupAttributes", resource, None))
        }
        _ => None,
    }
}

fn resolve_multi_region_endpoints_action(
    method: &Method,
    segs: &[String],
    resource: Option<String>,
) -> ResolvedAction {
    match (method, segs.len()) {
        (&Method::POST, 3) => Some(("CreateMultiRegionEndpoint", None, None)),
        (&Method::GET, 3) => Some(("ListMultiRegionEndpoints", None, None)),
        (&Method::GET, 4) => Some(("GetMultiRegionEndpoint", resource, None)),
        (&Method::DELETE, 4) => Some(("DeleteMultiRegionEndpoint", resource, None)),
        _ => None,
    }
}

fn resolve_import_jobs_action(
    method: &Method,
    segs: &[String],
    resource: Option<String>,
) -> ResolvedAction {
    match (method, segs.len()) {
        (&Method::POST, 3) => Some(("CreateImportJob", None, None)),
        (&Method::POST, 4) if segs[3] == "list" => Some(("ListImportJobs", None, None)),
        (&Method::GET, 4) => Some(("GetImportJob", resource, None)),
        _ => None,
    }
}

fn resolve_export_jobs_action(
    method: &Method,
    segs: &[String],
    resource: Option<String>,
) -> ResolvedAction {
    match (method, segs.len()) {
        (&Method::POST, 3) => Some(("CreateExportJob", None, None)),
        (&Method::GET, 4) => Some(("GetExportJob", resource, None)),
        (&Method::PUT, 5) if segs[4] == "cancel" => Some(("CancelExportJob", resource, None)),
        _ => None,
    }
}

fn resolve_tenants_action(method: &Method, segs: &[String]) -> ResolvedAction {
    match (method, segs.len()) {
        (&Method::POST, 3) => Some(("CreateTenant", None, None)),
        (&Method::POST, 4) if segs[3] == "list" => Some(("ListTenants", None, None)),
        (&Method::POST, 4) if segs[3] == "get" => Some(("GetTenant", None, None)),
        (&Method::POST, 4) if segs[3] == "delete" => Some(("DeleteTenant", None, None)),
        (&Method::POST, 4) if segs[3] == "resources" => {
            Some(("CreateTenantResourceAssociation", None, None))
        }
        (&Method::POST, 5) if segs[3] == "resources" && segs[4] == "delete" => {
            Some(("DeleteTenantResourceAssociation", None, None))
        }
        (&Method::POST, 5) if segs[3] == "resources" && segs[4] == "list" => {
            Some(("ListTenantResources", None, None))
        }
        _ => None,
    }
}

fn resolve_resources_action(method: &Method, segs: &[String]) -> ResolvedAction {
    match (method, segs.len()) {
        (&Method::POST, 5) if segs[3] == "tenants" && segs[4] == "list" => {
            Some(("ListResourceTenants", None, None))
        }
        _ => None,
    }
}

fn resolve_reputation_action(method: &Method, segs: &[String]) -> ResolvedAction {
    if segs.get(3).map(|s| s.as_str()) != Some("entities") {
        return None;
    }
    match (method, segs.len()) {
        (&Method::POST, 4) => Some(("ListReputationEntities", None, None)),
        (&Method::GET, 6) => Some((
            "GetReputationEntity",
            Some(decode_segment(&segs[4])),
            Some(decode_segment(&segs[5])),
        )),
        (&Method::PUT, 7) if segs[6] == "customer-managed-status" => Some((
            "UpdateReputationEntityCustomerManagedStatus",
            Some(decode_segment(&segs[4])),
            Some(decode_segment(&segs[5])),
        )),
        (&Method::PUT, 7) if segs[6] == "policy" => Some((
            "UpdateReputationEntityPolicy",
            Some(decode_segment(&segs[4])),
            Some(decode_segment(&segs[5])),
        )),
        _ => None,
    }
}

fn parse_topics(value: &Value) -> Vec<Topic> {
    value
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    let topic_name = v["TopicName"].as_str()?.to_string();
                    let display_name = v["DisplayName"].as_str().unwrap_or("").to_string();
                    let description = v["Description"].as_str().unwrap_or("").to_string();
                    let default_subscription_status = v["DefaultSubscriptionStatus"]
                        .as_str()
                        .unwrap_or("OPT_OUT")
                        .to_string();
                    Some(Topic {
                        topic_name,
                        display_name,
                        description,
                        default_subscription_status,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_topic_preferences(value: &Value) -> Vec<TopicPreference> {
    value
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    let topic_name = v["TopicName"].as_str()?.to_string();
                    let subscription_status = v["SubscriptionStatus"]
                        .as_str()
                        .unwrap_or("OPT_OUT")
                        .to_string();
                    Some(TopicPreference {
                        topic_name,
                        subscription_status,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn extract_string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_event_destination_definition(name: &str, def: &Value) -> EventDestination {
    let enabled = def["Enabled"].as_bool().unwrap_or(false);
    let matching_event_types = extract_string_array(&def["MatchingEventTypes"]);
    let kinesis_firehose_destination = def
        .get("KinesisFirehoseDestination")
        .filter(|v| v.is_object())
        .cloned();
    let cloud_watch_destination = def
        .get("CloudWatchDestination")
        .filter(|v| v.is_object())
        .cloned();
    let sns_destination = def.get("SnsDestination").filter(|v| v.is_object()).cloned();
    let event_bridge_destination = def
        .get("EventBridgeDestination")
        .filter(|v| v.is_object())
        .cloned();
    let pinpoint_destination = def
        .get("PinpointDestination")
        .filter(|v| v.is_object())
        .cloned();

    EventDestination {
        name: name.to_string(),
        enabled,
        matching_event_types,
        kinesis_firehose_destination,
        cloud_watch_destination,
        sns_destination,
        event_bridge_destination,
        pinpoint_destination,
    }
}

fn event_destination_to_json(dest: &EventDestination) -> Value {
    let mut obj = json!({
        "Name": dest.name,
        "Enabled": dest.enabled,
        "MatchingEventTypes": dest.matching_event_types,
    });
    if let Some(ref v) = dest.kinesis_firehose_destination {
        obj["KinesisFirehoseDestination"] = v.clone();
    }
    if let Some(ref v) = dest.cloud_watch_destination {
        obj["CloudWatchDestination"] = v.clone();
    }
    if let Some(ref v) = dest.sns_destination {
        obj["SnsDestination"] = v.clone();
    }
    if let Some(ref v) = dest.event_bridge_destination {
        obj["EventBridgeDestination"] = v.clone();
    }
    if let Some(ref v) = dest.pinpoint_destination {
        obj["PinpointDestination"] = v.clone();
    }
    obj
}

fn is_mutating_action(action: &str) -> bool {
    const MUTATING_PREFIXES: &[&str] = &[
        "Create",
        "Update",
        "Delete",
        "Put",
        "Tag",
        "Untag",
        "Send",
        "Cancel",
        "Verify",
        "Set",
        "Clone",
        "Reorder",
        "BatchUpdate",
    ];
    MUTATING_PREFIXES.iter().any(|p| action.starts_with(p))
}

#[async_trait]
impl fakecloud_core::service::AwsService for SesV2Service {
    fn service_name(&self) -> &str {
        "ses"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // Route v1 Query protocol requests to the v1 module.
        if req.is_query_protocol {
            let mutates = is_mutating_action(req.action.as_str());
            let result = crate::v1::handle_v1_action(&self.state, &req);
            if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
                self.save_snapshot().await;
            }
            return result;
        }

        let (action, resource_name, sub_resource) =
            Self::resolve_action(&req).ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "UnknownOperationException",
                    format!("Unknown operation: {} {}", req.method, req.raw_path),
                )
            })?;

        let res = resource_name.as_deref().unwrap_or("");
        let sub = sub_resource.as_deref().unwrap_or("");
        let mutates = is_mutating_action(action);

        let result = match action {
            "GetAccount" => self.get_account(&req),
            "CreateEmailIdentity" => self.create_email_identity(&req),
            "ListEmailIdentities" => self.list_email_identities(&req),
            "GetEmailIdentity" => self.get_email_identity(res, &req),
            "DeleteEmailIdentity" => self.delete_email_identity(res, &req),
            "CreateConfigurationSet" => self.create_configuration_set(&req),
            "ListConfigurationSets" => self.list_configuration_sets(&req),
            "GetConfigurationSet" => self.get_configuration_set(res, &req),
            "DeleteConfigurationSet" => self.delete_configuration_set(res, &req),
            "CreateEmailTemplate" => self.create_email_template(&req),
            "ListEmailTemplates" => self.list_email_templates(&req),
            "GetEmailTemplate" => self.get_email_template(res, &req),
            "UpdateEmailTemplate" => self.update_email_template(res, &req),
            "DeleteEmailTemplate" => self.delete_email_template(res, &req),
            "SendEmail" => self.send_email(&req),
            "SendBulkEmail" => self.send_bulk_email(&req),
            "TagResource" => self.tag_resource(&req),
            "UntagResource" => self.untag_resource(&req),
            "ListTagsForResource" => self.list_tags_for_resource(&req),
            "CreateContactList" => self.create_contact_list(&req),
            "GetContactList" => self.get_contact_list(res, &req),
            "ListContactLists" => self.list_contact_lists(&req),
            "UpdateContactList" => self.update_contact_list(res, &req),
            "DeleteContactList" => self.delete_contact_list(res, &req),
            "CreateContact" => self.create_contact(res, &req),
            "GetContact" => self.get_contact(res, sub, &req),
            "ListContacts" => self.list_contacts(res, &req),
            "UpdateContact" => self.update_contact(res, sub, &req),
            "DeleteContact" => self.delete_contact(res, sub, &req),
            "PutSuppressedDestination" => self.put_suppressed_destination(&req),
            "GetSuppressedDestination" => self.get_suppressed_destination(res, &req),
            "DeleteSuppressedDestination" => self.delete_suppressed_destination(res, &req),
            "ListSuppressedDestinations" => self.list_suppressed_destinations(&req),
            "CreateConfigurationSetEventDestination" => {
                self.create_configuration_set_event_destination(res, &req)
            }
            "GetConfigurationSetEventDestinations" => {
                self.get_configuration_set_event_destinations(res, &req)
            }
            "UpdateConfigurationSetEventDestination" => {
                self.update_configuration_set_event_destination(res, sub, &req)
            }
            "DeleteConfigurationSetEventDestination" => {
                self.delete_configuration_set_event_destination(res, sub, &req)
            }
            "CreateEmailIdentityPolicy" => self.create_email_identity_policy(res, sub, &req),
            "GetEmailIdentityPolicies" => self.get_email_identity_policies(res, &req),
            "UpdateEmailIdentityPolicy" => self.update_email_identity_policy(res, sub, &req),
            "DeleteEmailIdentityPolicy" => self.delete_email_identity_policy(res, sub, &req),
            "PutEmailIdentityDkimAttributes" => self.put_email_identity_dkim_attributes(res, &req),
            "PutEmailIdentityDkimSigningAttributes" => {
                self.put_email_identity_dkim_signing_attributes(res, &req)
            }
            "PutEmailIdentityFeedbackAttributes" => {
                self.put_email_identity_feedback_attributes(res, &req)
            }
            "PutEmailIdentityMailFromAttributes" => {
                self.put_email_identity_mail_from_attributes(res, &req)
            }
            "PutEmailIdentityConfigurationSetAttributes" => {
                self.put_email_identity_configuration_set_attributes(res, &req)
            }
            "PutConfigurationSetSendingOptions" => {
                self.put_configuration_set_sending_options(res, &req)
            }
            "PutConfigurationSetDeliveryOptions" => {
                self.put_configuration_set_delivery_options(res, &req)
            }
            "PutConfigurationSetTrackingOptions" => {
                self.put_configuration_set_tracking_options(res, &req)
            }
            "PutConfigurationSetSuppressionOptions" => {
                self.put_configuration_set_suppression_options(res, &req)
            }
            "PutConfigurationSetReputationOptions" => {
                self.put_configuration_set_reputation_options(res, &req)
            }
            "PutConfigurationSetVdmOptions" => self.put_configuration_set_vdm_options(res, &req),
            "PutConfigurationSetArchivingOptions" => {
                self.put_configuration_set_archiving_options(res, &req)
            }
            "CreateCustomVerificationEmailTemplate" => {
                self.create_custom_verification_email_template(&req)
            }
            "GetCustomVerificationEmailTemplate" => {
                self.get_custom_verification_email_template(res, &req)
            }
            "ListCustomVerificationEmailTemplates" => {
                self.list_custom_verification_email_templates(&req)
            }
            "UpdateCustomVerificationEmailTemplate" => {
                self.update_custom_verification_email_template(res, &req)
            }
            "DeleteCustomVerificationEmailTemplate" => {
                self.delete_custom_verification_email_template(res, &req)
            }
            "SendCustomVerificationEmail" => self.send_custom_verification_email(&req),
            "TestRenderEmailTemplate" => self.test_render_email_template(res, &req),
            "CreateDedicatedIpPool" => self.create_dedicated_ip_pool(&req),
            "ListDedicatedIpPools" => self.list_dedicated_ip_pools(&req),
            "DeleteDedicatedIpPool" => self.delete_dedicated_ip_pool(res, &req),
            "GetDedicatedIp" => self.get_dedicated_ip(res, &req),
            "GetDedicatedIps" => self.get_dedicated_ips(&req),
            "PutDedicatedIpInPool" => self.put_dedicated_ip_in_pool(res, &req),
            "PutDedicatedIpPoolScalingAttributes" => {
                self.put_dedicated_ip_pool_scaling_attributes(res, &req)
            }
            "PutDedicatedIpWarmupAttributes" => self.put_dedicated_ip_warmup_attributes(res, &req),
            "PutAccountDedicatedIpWarmupAttributes" => {
                self.put_account_dedicated_ip_warmup_attributes(&req)
            }
            "CreateMultiRegionEndpoint" => self.create_multi_region_endpoint(&req),
            "GetMultiRegionEndpoint" => self.get_multi_region_endpoint(res, &req),
            "ListMultiRegionEndpoints" => self.list_multi_region_endpoints(&req),
            "DeleteMultiRegionEndpoint" => self.delete_multi_region_endpoint(res, &req),
            "PutAccountDetails" => self.put_account_details(&req),
            "PutAccountSendingAttributes" => self.put_account_sending_attributes(&req),
            "PutAccountSuppressionAttributes" => self.put_account_suppression_attributes(&req),
            "PutAccountVdmAttributes" => self.put_account_vdm_attributes(&req),
            "CreateImportJob" => self.create_import_job(&req),
            "GetImportJob" => self.get_import_job(res, &req),
            "ListImportJobs" => self.list_import_jobs(&req),
            "CreateExportJob" => self.create_export_job(&req),
            "GetExportJob" => self.get_export_job(res, &req),
            "ListExportJobs" => self.list_export_jobs(&req),
            "CancelExportJob" => self.cancel_export_job(res, &req),
            "CreateTenant" => self.create_tenant(&req),
            "GetTenant" => self.get_tenant(&req),
            "ListTenants" => self.list_tenants(&req),
            "DeleteTenant" => self.delete_tenant(&req),
            "CreateTenantResourceAssociation" => self.create_tenant_resource_association(&req),
            "DeleteTenantResourceAssociation" => self.delete_tenant_resource_association(&req),
            "ListTenantResources" => self.list_tenant_resources(&req),
            "ListResourceTenants" => self.list_resource_tenants(&req),
            "GetReputationEntity" => self.get_reputation_entity(res, sub, &req),
            "ListReputationEntities" => self.list_reputation_entities(&req),
            "UpdateReputationEntityCustomerManagedStatus" => {
                self.update_reputation_entity_customer_managed_status(res, sub, &req)
            }
            "UpdateReputationEntityPolicy" => self.update_reputation_entity_policy(res, sub, &req),
            "BatchGetMetricData" => self.batch_get_metric_data(&req),
            "GetDedicatedIpPool" => self.get_dedicated_ip_pool(res, &req),
            "GetDeliverabilityDashboardOptions" => self.get_deliverability_dashboard_options(&req),
            "PutDeliverabilityDashboardOption" => self.put_deliverability_dashboard_option(&req),
            "CreateDeliverabilityTestReport" => self.create_deliverability_test_report(&req),
            "GetDeliverabilityTestReport" => self.get_deliverability_test_report(res, &req),
            "ListDeliverabilityTestReports" => self.list_deliverability_test_reports(&req),
            "GetBlacklistReports" => self.get_blacklist_reports(&req),
            "GetDomainDeliverabilityCampaign" => self.get_domain_deliverability_campaign(res, &req),
            "GetDomainStatisticsReport" => self.get_domain_statistics_report(res, &req),
            "ListDomainDeliverabilityCampaigns" => {
                self.list_domain_deliverability_campaigns(res, &req)
            }
            "GetEmailAddressInsights" => self.get_email_address_insights(&req),
            "GetMessageInsights" => self.get_message_insights(res, &req),
            "ListRecommendations" => self.list_recommendations(&req),
            _ => Err(AwsServiceError::action_not_implemented("ses", action)),
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            self.save_snapshot().await;
        }
        result
    }

    fn supported_actions(&self) -> &[&str] {
        &[
            "GetAccount",
            "CreateEmailIdentity",
            "ListEmailIdentities",
            "GetEmailIdentity",
            "DeleteEmailIdentity",
            "CreateConfigurationSet",
            "ListConfigurationSets",
            "GetConfigurationSet",
            "DeleteConfigurationSet",
            "CreateEmailTemplate",
            "ListEmailTemplates",
            "GetEmailTemplate",
            "UpdateEmailTemplate",
            "DeleteEmailTemplate",
            "SendEmail",
            "SendBulkEmail",
            "TagResource",
            "UntagResource",
            "ListTagsForResource",
            "CreateContactList",
            "GetContactList",
            "ListContactLists",
            "UpdateContactList",
            "DeleteContactList",
            "CreateContact",
            "GetContact",
            "ListContacts",
            "UpdateContact",
            "DeleteContact",
            "PutSuppressedDestination",
            "GetSuppressedDestination",
            "DeleteSuppressedDestination",
            "ListSuppressedDestinations",
            "CreateConfigurationSetEventDestination",
            "GetConfigurationSetEventDestinations",
            "UpdateConfigurationSetEventDestination",
            "DeleteConfigurationSetEventDestination",
            "CreateEmailIdentityPolicy",
            "GetEmailIdentityPolicies",
            "UpdateEmailIdentityPolicy",
            "DeleteEmailIdentityPolicy",
            "PutEmailIdentityDkimAttributes",
            "PutEmailIdentityDkimSigningAttributes",
            "PutEmailIdentityFeedbackAttributes",
            "PutEmailIdentityMailFromAttributes",
            "PutEmailIdentityConfigurationSetAttributes",
            "PutConfigurationSetSendingOptions",
            "PutConfigurationSetDeliveryOptions",
            "PutConfigurationSetTrackingOptions",
            "PutConfigurationSetSuppressionOptions",
            "PutConfigurationSetReputationOptions",
            "PutConfigurationSetVdmOptions",
            "PutConfigurationSetArchivingOptions",
            "CreateCustomVerificationEmailTemplate",
            "GetCustomVerificationEmailTemplate",
            "ListCustomVerificationEmailTemplates",
            "UpdateCustomVerificationEmailTemplate",
            "DeleteCustomVerificationEmailTemplate",
            "SendCustomVerificationEmail",
            "TestRenderEmailTemplate",
            "CreateDedicatedIpPool",
            "ListDedicatedIpPools",
            "DeleteDedicatedIpPool",
            "GetDedicatedIp",
            "GetDedicatedIps",
            "PutDedicatedIpInPool",
            "PutDedicatedIpPoolScalingAttributes",
            "PutDedicatedIpWarmupAttributes",
            "PutAccountDedicatedIpWarmupAttributes",
            "CreateMultiRegionEndpoint",
            "GetMultiRegionEndpoint",
            "ListMultiRegionEndpoints",
            "DeleteMultiRegionEndpoint",
            "PutAccountDetails",
            "PutAccountSendingAttributes",
            "PutAccountSuppressionAttributes",
            "PutAccountVdmAttributes",
            "CreateImportJob",
            "GetImportJob",
            "ListImportJobs",
            "CreateExportJob",
            "GetExportJob",
            "ListExportJobs",
            "CancelExportJob",
            "CreateTenant",
            "GetTenant",
            "ListTenants",
            "DeleteTenant",
            "CreateTenantResourceAssociation",
            "DeleteTenantResourceAssociation",
            "ListTenantResources",
            "ListResourceTenants",
            "GetReputationEntity",
            "ListReputationEntities",
            "UpdateReputationEntityCustomerManagedStatus",
            "UpdateReputationEntityPolicy",
            "BatchGetMetricData",
            "GetDedicatedIpPool",
            "GetDeliverabilityDashboardOptions",
            "PutDeliverabilityDashboardOption",
            "CreateDeliverabilityTestReport",
            "GetDeliverabilityTestReport",
            "ListDeliverabilityTestReports",
            "GetBlacklistReports",
            "GetDomainDeliverabilityCampaign",
            "GetDomainStatisticsReport",
            "ListDomainDeliverabilityCampaigns",
            "GetEmailAddressInsights",
            "GetMessageInsights",
            "ListRecommendations",
            // NOTE: SES v1 receipt rule/filter actions are implemented (see v1.rs)
            // but excluded from the conformance audit because there is no SES v1
            // Smithy model (only sesv2.json exists) to generate checksums from.
        ]
    }
}

#[cfg(test)]
mod tests;
