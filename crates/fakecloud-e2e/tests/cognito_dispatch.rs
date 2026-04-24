//! Cognito routes verification emails through SES and SMS through SNS.
//! Test asserts via the existing /_fakecloud/ses/emails and a new
//! /_fakecloud/sns/sms introspection endpoint.

mod helpers;

use aws_sdk_cognitoidentityprovider::types::{
    AttributeType, ExplicitAuthFlowsType, PasswordPolicyType, UserPoolPolicyType,
};
use helpers::TestServer;

#[tokio::test]
async fn cognito_signup_dispatches_verification_email_via_ses() {
    let server = TestServer::start().await;
    let client = server.cognito_client().await;
    let http = reqwest::Client::new();

    let pool = client
        .create_user_pool()
        .pool_name("dispatch-pool")
        .policies(
            UserPoolPolicyType::builder()
                .password_policy(
                    PasswordPolicyType::builder()
                        .minimum_length(6)
                        .require_uppercase(false)
                        .require_lowercase(false)
                        .require_numbers(false)
                        .require_symbols(false)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let pool_id = pool.user_pool().unwrap().id().unwrap().to_string();

    let pc = client
        .create_user_pool_client()
        .user_pool_id(&pool_id)
        .client_name("dispatch-client")
        .explicit_auth_flows(ExplicitAuthFlowsType::AllowUserPasswordAuth)
        .send()
        .await
        .unwrap();
    let client_id = pc
        .user_pool_client()
        .unwrap()
        .client_id()
        .unwrap()
        .to_string();

    client
        .sign_up()
        .client_id(&client_id)
        .username("alice")
        .password("hunter2")
        .user_attributes(
            AttributeType::builder()
                .name("email")
                .value("alice@example.com")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    // Read confirmation code so we can assert it's the same code that
    // landed in the SES sent-emails table.
    let code_resp: serde_json::Value = http
        .get(format!(
            "{}/_fakecloud/cognito/confirmation-codes/{}/alice",
            server.endpoint(),
            pool_id
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let code = code_resp["confirmationCode"].as_str().unwrap().to_string();

    // SES dispatch happens fire-and-forget — give it a beat.
    let mut found: Option<serde_json::Value> = None;
    for _ in 0..30 {
        let emails: serde_json::Value = http
            .get(format!("{}/_fakecloud/ses/emails", server.endpoint()))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if let Some(arr) = emails["emails"].as_array() {
            if let Some(e) = arr.iter().find(|e| {
                e["to"]
                    .as_array()
                    .map(|to| to.iter().any(|t| t.as_str() == Some("alice@example.com")))
                    .unwrap_or(false)
            }) {
                found = Some(e.clone());
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let email = found.expect("verification email not dispatched to SES");
    let body = email["textBody"].as_str().unwrap_or("");
    assert!(
        body.contains(&code),
        "expected verification code {code} in email body, got {body}"
    );
    let subject = email["subject"].as_str().unwrap_or("");
    assert!(!subject.is_empty(), "expected verification subject");
}

#[tokio::test]
async fn cognito_get_user_attribute_phone_dispatches_sms_via_sns() {
    let server = TestServer::start().await;
    let client = server.cognito_client().await;
    let http = reqwest::Client::new();

    let pool = client
        .create_user_pool()
        .pool_name("sms-pool")
        .policies(
            UserPoolPolicyType::builder()
                .password_policy(
                    PasswordPolicyType::builder()
                        .minimum_length(6)
                        .require_uppercase(false)
                        .require_lowercase(false)
                        .require_numbers(false)
                        .require_symbols(false)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let pool_id = pool.user_pool().unwrap().id().unwrap().to_string();

    let pc = client
        .create_user_pool_client()
        .user_pool_id(&pool_id)
        .client_name("sms-client")
        .explicit_auth_flows(ExplicitAuthFlowsType::AllowUserPasswordAuth)
        .explicit_auth_flows(ExplicitAuthFlowsType::AllowAdminUserPasswordAuth)
        .send()
        .await
        .unwrap();
    let client_id = pc
        .user_pool_client()
        .unwrap()
        .client_id()
        .unwrap()
        .to_string();

    client
        .admin_create_user()
        .user_pool_id(&pool_id)
        .username("bob")
        .user_attributes(
            AttributeType::builder()
                .name("phone_number")
                .value("+15551234567")
                .build()
                .unwrap(),
        )
        .message_action(aws_sdk_cognitoidentityprovider::types::MessageActionType::Suppress)
        .send()
        .await
        .unwrap();
    client
        .admin_set_user_password()
        .user_pool_id(&pool_id)
        .username("bob")
        .password("hunter2")
        .permanent(true)
        .send()
        .await
        .unwrap();

    // Sign in to get an AccessToken
    let auth = client
        .admin_initiate_auth()
        .user_pool_id(&pool_id)
        .client_id(&client_id)
        .auth_flow(aws_sdk_cognitoidentityprovider::types::AuthFlowType::AdminUserPasswordAuth)
        .auth_parameters("USERNAME", "bob")
        .auth_parameters("PASSWORD", "hunter2")
        .send()
        .await
        .unwrap();
    let access_token = auth
        .authentication_result()
        .unwrap()
        .access_token()
        .unwrap()
        .to_string();

    client
        .get_user_attribute_verification_code()
        .access_token(&access_token)
        .attribute_name("phone_number")
        .send()
        .await
        .unwrap();

    let mut found: Option<serde_json::Value> = None;
    for _ in 0..30 {
        let resp: serde_json::Value = http
            .get(format!("{}/_fakecloud/sns/sms", server.endpoint()))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if let Some(arr) = resp["messages"].as_array() {
            if let Some(m) = arr
                .iter()
                .find(|m| m["phoneNumber"].as_str() == Some("+15551234567"))
            {
                found = Some(m.clone());
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let sms = found.expect("verification SMS not dispatched to SNS");
    let msg = sms["message"].as_str().unwrap_or("");
    assert!(!msg.is_empty(), "expected SMS message body");
    // Default template includes the 6-digit code.
    let digits: String = msg.chars().filter(|c| c.is_ascii_digit()).collect();
    assert!(
        digits.len() >= 6,
        "expected verification code in SMS: {msg}"
    );
}

#[tokio::test]
async fn cognito_custom_email_sender_lambda_takes_precedence_over_ses() {
    use aws_sdk_lambda::types::{FunctionCode, Runtime};

    let server = TestServer::start().await;
    let cognito = server.cognito_client().await;
    let lambda = server.lambda_client().await;
    let iam = server.iam_client().await;
    let http = reqwest::Client::new();

    // Trivial Lambda we can register; the trigger is fire-and-forget so
    // the body doesn't have to do anything functional, just exist.
    iam.create_role()
        .role_name("cognito-custom-sender-role")
        .assume_role_policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#,
        )
        .send()
        .await
        .unwrap();
    let zip_bytes = build_python_handler_zip();
    lambda
        .create_function()
        .function_name("custom-email-sender")
        .runtime(Runtime::Python311)
        .role("arn:aws:iam::123456789012:role/cognito-custom-sender-role")
        .handler("index.handler")
        .code(FunctionCode::builder().zip_file(zip_bytes.into()).build())
        .send()
        .await
        .unwrap();

    let pool = cognito
        .create_user_pool()
        .pool_name("custom-sender-pool")
        .lambda_config(
            aws_sdk_cognitoidentityprovider::types::LambdaConfigType::builder()
                .custom_email_sender(
                    aws_sdk_cognitoidentityprovider::types::CustomEmailLambdaVersionConfigType::builder()
                        .lambda_arn("arn:aws:lambda:us-east-1:123456789012:function:custom-email-sender")
                        .lambda_version(aws_sdk_cognitoidentityprovider::types::CustomEmailSenderLambdaVersionType::V10)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .policies(
            UserPoolPolicyType::builder()
                .password_policy(
                    PasswordPolicyType::builder()
                        .minimum_length(6)
                        .require_uppercase(false)
                        .require_lowercase(false)
                        .require_numbers(false)
                        .require_symbols(false)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let pool_id = pool.user_pool().unwrap().id().unwrap().to_string();

    let pc = cognito
        .create_user_pool_client()
        .user_pool_id(&pool_id)
        .client_name("custom-sender-client")
        .explicit_auth_flows(ExplicitAuthFlowsType::AllowUserPasswordAuth)
        .send()
        .await
        .unwrap();
    let client_id = pc
        .user_pool_client()
        .unwrap()
        .client_id()
        .unwrap()
        .to_string();

    cognito
        .sign_up()
        .client_id(&client_id)
        .username("charlie")
        .password("hunter2")
        .user_attributes(
            AttributeType::builder()
                .name("email")
                .value("charlie@example.com")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    // Wait a beat for the dispatch task to finish.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // CustomEmailSender is configured -> SES path must NOT have run.
    let emails: serde_json::Value = http
        .get(format!("{}/_fakecloud/ses/emails", server.endpoint()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let to_charlie = emails["emails"]
        .as_array()
        .map(|arr| {
            arr.iter().any(|e| {
                e["to"]
                    .as_array()
                    .map(|to| to.iter().any(|t| t.as_str() == Some("charlie@example.com")))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    assert!(
        !to_charlie,
        "CustomEmailSender configured should suppress SES dispatch"
    );
}

fn build_python_handler_zip() -> Vec<u8> {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<'_, ()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file("index.py", opts).unwrap();
        zip.write_all(b"def handler(event, context):\n    return event\n")
            .unwrap();
        zip.finish().unwrap();
    }
    buf
}
