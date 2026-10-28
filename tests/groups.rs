mod common;
use common::*;

use axum::http::StatusCode;
use serde_json::{json, Value};

#[tokio::test]
async fn admin_group_crud() {
    let ctx = new_test_ctx();
    let (app_id, _key, _secret) = create_app_quota(&ctx.admin, "G", 1 << 20, 1 << 20).await;

    // create a group
    let (s, v) = json_of(
        send(
            &ctx.admin,
            admin_req("POST", &format!("/admin/v1/apps/{app_id}/groups"), json!({ "name": "eng" })),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["name"], "eng");
    assert_eq!(v["members"].as_array().unwrap().len(), 0);

    // invalid names are rejected (empty, space, path separators)
    for bad in ["", "a b", "a/b", "a\\b"] {
        let (s, v) = json_of(
            send(
                &ctx.admin,
                admin_req("POST", &format!("/admin/v1/apps/{app_id}/groups"), json!({ "name": bad })),
            )
            .await,
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "group name {bad:?} must be rejected: {v}");
    }

    // duplicate name is rejected
    let (s, _) = json_of(
        send(
            &ctx.admin,
            admin_req("POST", &format!("/admin/v1/apps/{app_id}/groups"), json!({ "name": "eng" })),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // unknown app -> 404
    let (s, _) = json_of(
        send(
            &ctx.admin,
            admin_req("POST", "/admin/v1/apps/9999/groups", json!({ "name": "x" })),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // add members
    let (s, v) = json_of(
        send(
            &ctx.admin,
            admin_req("POST", &format!("/admin/v1/apps/{app_id}/groups/eng/members"), json!({ "user_id": "alice" })),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["members"][0], "alice");

    let (s, _) = json_of(
        send(
            &ctx.admin,
            admin_req("POST", &format!("/admin/v1/apps/{app_id}/groups/eng/members"), json!({ "user_id": "bob" })),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // adding an existing member is idempotent (no duplicate)
    let (s, v) = json_of(
        send(
            &ctx.admin,
            admin_req("POST", &format!("/admin/v1/apps/{app_id}/groups/eng/members"), json!({ "user_id": "alice" })),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["members"].as_array().unwrap().len(), 2);

    // get a single group
    let (s, v) = json_of(
        send(&ctx.admin, admin_req("GET", &format!("/admin/v1/apps/{app_id}/groups/eng"), json!(null))).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["members"].as_array().unwrap().len(), 2);

    // list groups
    let (s, v) = json_of(
        send(&ctx.admin, admin_req("GET", &format!("/admin/v1/apps/{app_id}/groups"), json!(null))).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["groups"].as_array().unwrap().len(), 1);

    // remove a member
    let (s, v) = json_of(
        send(&ctx.admin, admin_req("DELETE", &format!("/admin/v1/apps/{app_id}/groups/eng/members/alice"), json!(null))).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["members"].as_array().unwrap().len(), 1);

    // deleting a non-existent member is a no-op but still OK
    let (s, v) = json_of(
        send(&ctx.admin, admin_req("DELETE", &format!("/admin/v1/apps/{app_id}/groups/eng/members/ghost"), json!(null))).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["members"].as_array().unwrap().len(), 1);

    // delete the group, then it is gone
    let (s, _) = json_of(
        send(&ctx.admin, admin_req("DELETE", &format!("/admin/v1/apps/{app_id}/groups/eng"), json!(null))).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = json_of(
        send(&ctx.admin, admin_req("GET", &format!("/admin/v1/apps/{app_id}/groups/eng"), json!(null))).await,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn group_acl_controls_file_read() {
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "ACL", 1 << 20, 1 << 20).await;

    // admin: group "eng" with member alice
    let (s, v) = json_of(
        send(&ctx.admin, admin_req("POST", &format!("/admin/v1/apps/{app_id}/groups"), json!({ "name": "eng" }))).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = json_of(
        send(
            &ctx.admin,
            admin_req("POST", &format!("/admin/v1/apps/{app_id}/groups/eng/members"), json!({ "user_id": "alice" })),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // both users must be registered in app_users before their JWTs are accepted
    for u in ["alice", "bob"] {
        let (s, v) = json_of(
            send(
                &ctx.admin,
                admin_req("POST", &format!("/admin/v1/apps/{app_id}/users"), json!({ "user_id": u })),
            )
            .await,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }

    // app uploads a file (owner "owner_u")
    let (s, v) = upload_bytes(&ctx, &key, &secret, "owner_u", b"hello group acl", "").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let file_id = v["file_id"].as_i64().unwrap();

    // grant read to the group via the file ACL patch API
    let (s, v) = json_of(
        send(
            &ctx.public,
            signed_req(
                &key,
                &secret,
                "PATCH",
                &format!("/v1/files/{file_id}/acl"),
                "",
                json!({ "action": "read", "add": ["g:eng"] }),
                &[],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // alice (member of eng) can read file metadata via her user JWT
    let (s, v) = json_of(
        send(&ctx.public, jwt_req(&secret, app_id, "alice", "GET", &format!("/v1/files/{file_id}"), json!(null))).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "alice in group eng should be allowed: {v}");

    // bob (not in eng) is denied
    let (s, v) = json_of(
        send(&ctx.public, jwt_req(&secret, app_id, "bob", "GET", &format!("/v1/files/{file_id}"), json!(null))).await,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "bob not in group should be denied: {v}");

    // after removing alice from the group, she is also denied
    let (s, _) = json_of(
        send(&ctx.admin, admin_req("DELETE", &format!("/admin/v1/apps/{app_id}/groups/eng/members/alice"), json!(null))).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = json_of(
        send(&ctx.public, jwt_req(&secret, app_id, "alice", "GET", &format!("/v1/files/{file_id}"), json!(null))).await,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "alice removed from group should be denied");
}

#[tokio::test]
async fn app_manages_its_own_groups() {
    let ctx = new_test_ctx();
    let (app_id, key, secret) = create_app_quota(&ctx.admin, "APPG", 1 << 20, 1 << 20).await;

    // the app (X-App-Key + HMAC) creates a group
    let (s, v) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "POST", "/v1/groups", "", json!({ "name": "eng" }), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["name"], "eng");

    // add a member
    let (s, v) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "POST", "/v1/groups/eng/members", "", json!({ "user_id": "alice" }), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // duplicate group name -> 400
    let (s, _) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "POST", "/v1/groups", "", json!({ "name": "eng" }), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // adding to an unknown group -> 404
    let (s, _) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "POST", "/v1/groups/nope/members", "", json!({ "user_id": "alice" }), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // list + detail
    let (s, v) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "GET", "/v1/groups", "", json!(null), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["groups"].as_array().unwrap().len(), 1);
    let (s, v) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "GET", "/v1/groups/eng", "", json!(null), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["members"].as_array().unwrap().len(), 1);

    // a user JWT must NOT manage groups (app-level right only)
    let (s, _) = json_of(
        send(&ctx.admin, admin_req("POST", &format!("/admin/v1/apps/{app_id}/users"), json!({ "user_id": "u_jwt" }))).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = json_of(
        send(&ctx.public, jwt_req(&secret, app_id, "u_jwt", "POST", "/v1/groups", json!({ "name": "x" }))).await,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "user jwt must not create groups: {v}");

    // remove member, then delete group, then it is gone
    let (s, v) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "DELETE", "/v1/groups/eng/members/alice", "", json!(null), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["members"].as_array().unwrap().len(), 0);
    let (s, _) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "DELETE", "/v1/groups/eng", "", json!(null), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = json_of(
        send(&ctx.public, signed_req(&key, &secret, "GET", "/v1/groups/eng", "", json!(null), &[])).await,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}
