use revolt_database::{
    AuditLogEntryAction, Database, User, util::{permissions::DatabasePermissionQuery, reference::Reference}
};
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::State;
use rocket_empty::EmptyResponse;

use crate::util::audit_log_reason::AuditLogReason;

/// # Delete Role
///
/// Delete a server role by its id.
#[openapi(tag = "Server Permissions")]
#[delete("/<target>/roles/<role_id>")]
pub async fn delete(
    db: &State<Database>,
    user: User,
    reason: AuditLogReason,
    target: Reference<'_>,
    role_id: String,
) -> Result<EmptyResponse> {
    let mut server = target.as_server(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageRole)?;

    let member_rank = query.get_member_rank().unwrap_or(i64::MIN);

    if let Some(role) = server.roles.remove(&role_id) {
        if role.rank <= member_rank {
            return Err(create_error!(NotElevated));
        }

        role.delete(db, &server.id, &role_id)
            .await?;

        AuditLogEntryAction::RoleDelete { role: role_id.clone(), name: role.name }
            .insert(db, server.id, reason.0, user.id)
            .await;

        Ok(EmptyResponse)
    } else {
        Err(create_error!(NotFound))
    }
}
