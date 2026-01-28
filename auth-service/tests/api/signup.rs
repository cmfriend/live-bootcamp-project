use auth_service::{routes::SignupResponse, ErrorResponse};

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

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // The signup route should return a 400 HTTP status code if an invalid input is sent.
    // The input is considered invalid if:
    // - The email is empty or does not contain '@'
    // - The password is less than 8 characters

    // Create an array of invalid inputs. Then, iterate through the array and 
    // make HTTP calls to the signup route. Assert a 400 HTTP status code is returned.
    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({
            "email": "",
            "password": "password123",
            "requires2FA": true,
        }),
        serde_json::json!({
            "email": "invalidemailaddress.com",
            "password": "password123",
            "requires2FA": true,
        }),
        serde_json::json!({
            "email": get_random_email(),
            "password": "abc",
            "requires2FA": true,
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    // Call the signup route twice. The second request should fail with a 409 HTTP status code
    let app = TestApp::new().await;

    let email = get_random_email();

    let first_test =
        serde_json::json!({
            "email": email,
            "password": "password123",
            "requires2FA": true,
        });

    let first_response = app.post_signup(&first_test).await;

    assert_eq!(
        first_response.status().as_u16(),
        201,
        "Failed for input: {:?}",
        first_test
    );

    let second_test =
        serde_json::json!({
            "email": email,
            "password": "password123",
            "requires2FA": true,
        });

    let second_response = app.post_signup(&second_test).await;

    assert_eq!(
        second_response.status().as_u16(),
        409,
        "Failed for input: {:?}",
        second_test
    );

    assert_eq!(
        second_response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );
}
