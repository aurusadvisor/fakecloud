//! HTTP method + URI to action routing for Route 53's REST-XML API.

use http::Method;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub action: &'static str,
    pub id: Option<String>,
    pub second_id: Option<String>,
}

impl Route {
    fn just(action: &'static str) -> Self {
        Self {
            action,
            id: None,
            second_id: None,
        }
    }

    fn with_id(action: &'static str, id: &str) -> Self {
        Self {
            action,
            id: Some(id.to_string()),
            second_id: None,
        }
    }

    fn with_two(action: &'static str, id: &str, second: &str) -> Self {
        Self {
            action,
            id: Some(id.to_string()),
            second_id: Some(second.to_string()),
        }
    }
}

pub fn route(method: &Method, path: &str, _raw_query: &str) -> Option<Route> {
    let path = path.strip_prefix("/2013-04-01").unwrap_or(path);
    let path = path.trim_start_matches('/');
    let segs: Vec<&str> = if path.is_empty() {
        Vec::new()
    } else {
        path.split('/').collect()
    };

    match (method, segs.as_slice()) {
        // ─── Hosted Zones ────────────────────────────────────────────
        (&Method::POST, ["hostedzone"]) => Some(Route::just("CreateHostedZone")),
        (&Method::GET, ["hostedzone"]) => Some(Route::just("ListHostedZones")),
        (&Method::GET, ["hostedzone", id]) => Some(Route::with_id("GetHostedZone", id)),
        (&Method::DELETE, ["hostedzone", id]) => Some(Route::with_id("DeleteHostedZone", id)),
        (&Method::POST, ["hostedzone", id]) => Some(Route::with_id("UpdateHostedZoneComment", id)),
        (&Method::POST, ["hostedzone", id, "features"]) => {
            Some(Route::with_id("UpdateHostedZoneFeatures", id))
        }
        (&Method::GET, ["hostedzonecount"]) => Some(Route::just("GetHostedZoneCount")),
        (&Method::GET, ["hostedzonesbyname"]) => Some(Route::just("ListHostedZonesByName")),
        (&Method::GET, ["hostedzonelimit", id, lim_type]) => {
            Some(Route::with_two("GetHostedZoneLimit", id, lim_type))
        }

        // ─── Resource Record Sets ────────────────────────────────────
        (&Method::POST, ["hostedzone", id, "rrset"]) => {
            Some(Route::with_id("ChangeResourceRecordSets", id))
        }
        (&Method::GET, ["hostedzone", id, "rrset"]) => {
            Some(Route::with_id("ListResourceRecordSets", id))
        }

        // ─── Change tracking ─────────────────────────────────────────
        (&Method::GET, ["change", id]) => Some(Route::with_id("GetChange", id)),

        // ─── DNS Test ────────────────────────────────────────────────
        (&Method::GET, ["testdnsanswer"]) => Some(Route::just("TestDNSAnswer")),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_hosted_zone() {
        assert_eq!(
            route(&Method::POST, "/2013-04-01/hostedzone", ""),
            Some(Route::just("CreateHostedZone"))
        );
    }

    #[test]
    fn get_hosted_zone_strips_prefix() {
        assert_eq!(
            route(&Method::GET, "/2013-04-01/hostedzone/Z123", ""),
            Some(Route::with_id("GetHostedZone", "Z123"))
        );
    }

    #[test]
    fn change_rrsets() {
        assert_eq!(
            route(&Method::POST, "/2013-04-01/hostedzone/Z123/rrset", ""),
            Some(Route::with_id("ChangeResourceRecordSets", "Z123"))
        );
    }
}
