mod common;
use common::*;

use axum::http::StatusCode;
use serde_json::{json, Value};

#[tokio::test]
async fn user_acl_and_folder_inheritance_deny_wins() {
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;

    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"file-of-u1", "").await;
    assert_eq!(s, StatusCode::OK);
    let f1 = v["file_id"].as_i64().unwrap();
    // register u2
    let (s, _) = upload_bytes(&ctx, &key, &secret, "u2", b"x", "").await;
    assert_eq!(s, StatusCode::OK);

    // owner u1 can read
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u1", "GET", &format!("/v1/files/{f1}"), Value::Null)).await;
    assert_eq!(s, StatusCode::OK);
    // u2 cannot
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u2", "GET", &format!("/v1/files/{f1}"), Value::Null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // u2 cannot generate a link either
    let (s, _) = json_of(
        send(
            &ctx.public,
            jwt_req(&secret, app_id, "u2", "POST", "/v1/links/generate", json!({"file_id": f1})),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Create folder, grant read to u2, upload a file inside
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req(&key, &secret, "POST", "/v1/folders", "", json!({"name": "invoices"}), &[]),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let folder_id = v["folder_id"].as_i64().unwrap();

    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"invoice-content", &format!("folder_id={folder_id}")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let f2 = v["file_id"].as_i64().unwrap();

    // u2 cannot read yet (no ACL anywhere)
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u2", "GET", &format!("/v1/files/{f2}"), Value::Null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // grant folder read to u2
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req(
                &key,
                &secret,
                "PATCH",
                &format!("/v1/folders/{folder_id}/acl"),
                "",
                json!({"action": "read", "add": ["u2"]}),
                &[],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // u2 can now read f2 via folder inheritance
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u2", "GET", &format!("/v1/files/{f2}"), Value::Null)).await;
    assert_eq!(s, StatusCode::OK, "u2 should read via folder inheritance");

    // deny wins: add deny u2 on the folder -> u2 locked out despite allow
    let (s, _) = json_of(
        send(
            &ctx.public,
            signed_req(
                &key,
                &secret,
                "PATCH",
                &format!("/v1/folders/{folder_id}/acl"),
                "",
                json!({"action": "read", "add": [], "deny": ["u2"]}),
                &[],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u2", "GET", &format!("/v1/files/{f2}"), Value::Null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "inherited deny must win");
}

#[tokio::test]
async fn inherited_folder_deny_beats_file_explicit_acl() {
    // Regression for test report §5.1 (HIGH): a file-level explicit allow must
    // NOT override a deny inherited from the folder chain ("a file-level allow
    // cannot override an inherited deny").
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let (s, _) = upload_bytes(&ctx, &key, &secret, "u2", b"x", "").await;
    assert_eq!(s, StatusCode::OK);

    // folder with read u2 AND deny u2
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req(&key, &secret, "POST", "/v1/folders", "", json!({"name": "locked"}), &[]),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let folder_id = v["folder_id"].as_i64().unwrap();
    let (s, _) = json_of(
        send(
            &ctx.public,
            signed_req(
                &key,
                &secret,
                "PATCH",
                &format!("/v1/folders/{folder_id}/acl"),
                "",
                json!({"action": "read", "add": ["u2"], "deny": ["u2"]}),
                &[],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // u1 uploads into the folder
    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"confidential", &format!("folder_id={folder_id}")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let f2 = v["file_id"].as_i64().unwrap();
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u2", "GET", &format!("/v1/files/{f2}"), Value::Null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "u2 denied before file-level grant");

    // THE VULNERABILITY: file-level explicit allow for u2 must still be blocked
    // by the inherited folder deny.
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req(
                &key,
                &secret,
                "POST",
                "/v1/files/batch/acl",
                "",
                json!({"file_ids": [f2], "action": "read", "add": ["u2"]}),
                &[],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["updated"].as_i64().unwrap_or(0), 1);

    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u2", "GET", &format!("/v1/files/{f2}"), Value::Null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "file explicit ACL must not override inherited folder deny");

    // owner u1 keeps access
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u1", "GET", &format!("/v1/files/{f2}"), Value::Null)).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn batch_acl_app_level_only() {
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "A", 1 << 20, 1 << 20).await;
    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"f1", "").await;
    assert_eq!(s, StatusCode::OK);
    let f1 = v["file_id"].as_i64().unwrap();
    let (s, v) = upload_bytes(&ctx, &key, &secret, "u1", b"f2", "").await;
    assert_eq!(s, StatusCode::OK);
    let f2 = v["file_id"].as_i64().unwrap();
    let (s, _) = upload_bytes(&ctx, &key, &secret, "u3", b"z", "").await;
    assert_eq!(s, StatusCode::OK);

    // user JWT cannot batch
    let (s, _) = send(
        &ctx.public,
        jwt_req(
            &secret,
            app_id,
            "u1",
            "POST",
            "/v1/files/batch/acl",
            json!({"file_ids": [f1], "action": "read", "add": ["u3"]}),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // app-level batch works and is scoped to its own tenant
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req(
                &key,
                &secret,
                "POST",
                "/v1/files/batch/acl",
                "",
                json!({"file_ids": [f1, f2], "action": "read", "add": ["u3"]}),
                &[],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["updated"], json!(2));

    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u3", "GET", &format!("/v1/files/{f1}"), Value::Null)).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(&ctx.public, jwt_req(&secret, app_id, "u3", "GET", &format!("/v1/files/{f2}"), Value::Null)).await;
    assert_eq!(s, StatusCode::OK);
}
