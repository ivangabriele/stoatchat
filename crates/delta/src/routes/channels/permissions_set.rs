use revolt_database::{
    AuditLogEntryAction, Database, User, util::{permissions::DatabasePermissionQuery, reference::Reference}
};
use revolt_models::v0;
use revolt_permissions::{ChannelPermission, Override, OverrideField, calculate_channel_permissions};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

use crate::util::audit_log_reason::AuditLogReason;

/// # Set Role Permission
///
/// Sets permissions for the specified role in this channel.
///
/// Channel must be a `TextChannel` or `VoiceChannel`.
#[openapi(tag = "Channel Permissions")]
#[put("/<target>/permissions/<role_id>", data = "<data>", rank = 2)]
pub async fn set_role_permissions(
    db: &State<Database>,
    user: User,
    reason: AuditLogReason,
    target: Reference<'_>,
    role_id: String,
    data: Json<v0::DataSetRolePermissions>,
) -> Result<Json<v0::Channel>> {
    let mut channel = target.as_channel(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;

    permissions.throw_if_lacking_channel_permission(ChannelPermission::ManagePermissions)?;

    if let Some(server) = query.server_ref() {
        if let Some(role) = server.roles.get(&role_id) {
            if role.rank <= query.get_member_rank().unwrap_or(i64::MIN) {
                return Err(create_error!(NotElevated));
            }

            let current_value: Override = role.permissions.into();
            permissions
                .throw_permission_override(current_value, &data.permissions)
                .await?;

            let override_field: OverrideField = data.permissions.clone().into();

            let server_id = server.id.clone();

            channel
                .set_role_permission(db, &role_id, override_field.clone())
                .await?;

            AuditLogEntryAction::ChannelRolePermissionsEdit { channel: channel.id().to_string(), role: role_id, permissions: override_field }
                .insert(db, server_id, reason.0, user.id)
                .await;

            Ok(Json(channel.into()))
        } else {
            Err(create_error!(NotFound))
        }
    } else {
        Err(create_error!(InvalidOperation))
    }
}
