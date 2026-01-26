use auth_service::routes::SignupResponse;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({}),
        serde_json::json!({
            "invalidfield": null,
        }),
        serde_json::json!({
            "invalidfield": "invalidvalue",
        }),
        serde_json::json!({
            "email": null,
        }),
        serde_json::json!({
            "email": random_email,
        }),
        serde_json::json!({
            "password": null
        }),
        serde_json::json!({
            "password": "password123"
        }),
        serde_json::json!({
            "requires2FA": null,
        }),
        serde_json::json!({
            "requires2FA": false,
        }),
        serde_json::json!({
            "email": null,
            "password": null,
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
        }),
        serde_json::json!({
            "password": null,
            "requires2FA": null,
        }),
        serde_json::json!({
            "password": "password123",
            "requires2FA": true,
        }),
        serde_json::json!({
            "email": null,
            "requires2FA": null,
        }),
        serde_json::json!({
            "email": random_email,
            "requires2FA": true,
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({
            "email": get_random_email(),
            "password": "password123",
            "requires2FA": true,
        }),
        serde_json::json!({
            "email": get_random_email(),
            "password": "password456",
            "requires2FA": false,
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            201,
            "Failed for input: {:?}",
            test_case
        );

        assert_eq!(response.status().as_u16(), 201);

        let expected_response = SignupResponse {
            message: "User created successfully!".to_owned(),
        };

        // Assert that we are getting the correct response body!
        assert_eq!(
            response
                .json::<SignupResponse>()
                .await
                .expect("Could not deserialize response body to UserBody"),
            expected_response
        );
    }
}
