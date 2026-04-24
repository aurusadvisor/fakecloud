//! AWS ECR URI recognition + translation to the local fakecloud OCI v2 endpoint.
//!
//! Shared between ECS and Lambda container runtimes: when a task definition
//! or Lambda function references `<account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>`,
//! fakecloud can't pull from AWS — there is no AWS account. Instead we
//! translate the URI to `127.0.0.1:<server-port>/<repo>:<tag>` and pull
//! from fakecloud's own OCI v2 registry (which is just another route on
//! the same HTTP server). Docker treats `127.0.0.1:<port>` as an insecure
//! registry automatically on both Linux and Docker Desktop, so no daemon
//! config is required.

/// Detect whether `image` is an AWS private-ECR URI. Match shape:
/// `<any>.dkr.ecr.<any>.amazonaws.com/<path>[:<tag>|@sha256:<digest>]`.
pub fn is_aws_ecr_uri(image: &str) -> bool {
    image.contains(".dkr.ecr.") && image.contains(".amazonaws.com/")
}

/// If `image` is an AWS private-ECR URI, return the local-registry URI
/// that fakecloud's OCI v2 endpoint serves the same content at. Returns
/// `None` for any other reference (public ECR, Docker Hub, etc.) — those
/// go straight to the upstream daemon.
///
/// Docker's localhost-registry behaviour means the daemon on both Linux
/// and macOS Docker Desktop accepts `127.0.0.1:<port>` over plain HTTP.
pub fn translate_to_local(image: &str, server_port: u16) -> Option<String> {
    if !is_aws_ecr_uri(image) {
        return None;
    }
    let (_registry, path) = image.split_once(".amazonaws.com/")?;
    if path.is_empty() {
        return None;
    }
    Some(format!("127.0.0.1:{server_port}/{path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_private_ecr_uri() {
        assert!(is_aws_ecr_uri(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag"
        ));
        assert!(is_aws_ecr_uri(
            "123456789012.dkr.ecr.eu-west-2.amazonaws.com/team/svc:v1"
        ));
        assert!(!is_aws_ecr_uri("public.ecr.aws/lambda/python:3.12"));
        assert!(!is_aws_ecr_uri("docker.io/library/alpine:3.20"));
        assert!(!is_aws_ecr_uri("alpine:3.20"));
    }

    #[test]
    fn translates_private_ecr_uri() {
        assert_eq!(
            translate_to_local(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag",
                4566
            ),
            Some("127.0.0.1:4566/repo:tag".to_string())
        );
        assert_eq!(
            translate_to_local(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/team/svc:v1",
                8080
            ),
            Some("127.0.0.1:8080/team/svc:v1".to_string())
        );
        assert_eq!(
            translate_to_local(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/repo@sha256:abc",
                4566
            ),
            Some("127.0.0.1:4566/repo@sha256:abc".to_string())
        );
        assert_eq!(translate_to_local("alpine:3.20", 4566), None);
        assert_eq!(
            translate_to_local("public.ecr.aws/lambda/python:3.12", 4566),
            None
        );
    }

    #[test]
    fn rejects_empty_path() {
        assert_eq!(
            translate_to_local("123456789012.dkr.ecr.us-east-1.amazonaws.com/", 4566),
            None
        );
    }
}
