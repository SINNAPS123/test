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


def upgrade():
    # Add columns for subuser support
    op.add_column('user', sa.Column('parent_user_id', sa.Integer(), nullable=True))
    op.add_column('user', sa.Column('assigned_platoon', sa.String(length=50), nullable=True))
    op.add_column('user', sa.Column('allowed_modules', sa.Text(), nullable=True))
    # Self-referential foreign key for parent_user_id
    op.create_foreign_key(
        'fk_user_parent_user',
        'user', 'user',
        ['parent_user_id'], ['id'],
        ondelete=None
    )


def downgrade():
    # Drop foreign key then columns
    try:
        op.drop_constraint('fk_user_parent_user', 'user', type_='foreignkey')
    except Exception:
        # Some SQLite environments may not name constraints; ignore if missing
        pass
    op.drop_column('user', 'allowed_modules')
    op.drop_column('user', 'assigned_platoon')
    op.drop_column('user', 'parent_user_id')