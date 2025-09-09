"""Add subuser fields to User

Revision ID: 7c2f0a1b4e3a
Revises: 5b0118c4db82
Create Date: 2025-09-08 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7c2f0a1b4e3a'
down_revision = '5b0118c4db82'
branch_labels = None
depends_on = None


def _get_inspector():
    bind = op.get_bind()
    return sa.inspect(bind)


def upgrade():
    inspector = _get_inspector()
    existing_cols = {col["name"] for col in inspector.get_columns("user")}

    # Add columns only if they don't already exist (idempotent)
    cols_to_add = []
    if "parent_user_id" not in existing_cols:
        cols_to_add.append(sa.Column("parent_user_id", sa.Integer(), nullable=True))
    if "assigned_platoon" not in existing_cols:
        cols_to_add.append(sa.Column("assigned_platoon", sa.String(length=50), nullable=True))
    if "allowed_modules" not in existing_cols:
        cols_to_add.append(sa.Column("allowed_modules", sa.Text(), nullable=True))

    if cols_to_add:
        # Use batch_alter_table for SQLite compatibility
        with op.batch_alter_table("user", schema=None) as batch_op:
            for c in cols_to_add:
                batch_op.add_column(c)

    # Create self-referential foreign key only if not present already
    # Note: batch_alter_table recreates the table on SQLite to apply constraints
    fks = inspector.get_foreign_keys("user")
    has_parent_fk = any(
        (fk.get("name") == "fk_user_parent_user")
        or (fk.get("referred_table") == "user" and fk.get("constrained_columns") == ["parent_user_id"])
        for fk in fks
    )

    if not has_parent_fk and "parent_user_id" in (existing_cols | {"parent_user_id"}):
        with op.batch_alter_table("user", schema=None) as batch_op:
            batch_op.create_foreign_key(
                "fk_user_parent_user",
                "user",
                ["parent_user_id"],
                ["id"],
                ondelete=None,
            )


def downgrade():
    inspector = _get_inspector()
    # Drop FK if it exists
    fks = inspector.get_foreign_keys("user")
    if any(fk.get("name") == "fk_user_parent_user" or fk.get("constrained_columns") == ["parent_user_id"] for fk in fks):
        with op.batch_alter_table("user", schema=None) as batch_op:
            batch_op.drop_constraint("fk_user_parent_user", type_="foreignkey")

    # Drop columns if they exist
    existing_cols = {col["name"] for col in inspector.get_columns("user")}
    with op.batch_alter_table("user", schema=None) as batch_op:
        if "allowed_modules" in existing_cols:
            batch_op.drop_column("allowed_modules")
        if "assigned_platoon" in existing_cols:
            batch_op.drop_column("assigned_platoon")
        if "parent_user_id" in existing_cols:
            batch_op.drop_column("parent_user_id")