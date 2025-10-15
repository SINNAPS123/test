"""Add custom_slug to ScopedAccessCode

Revision ID: 9a1c2d3e4f56
Revises: 5b0118c4db82
Create Date: 2025-09-10 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9a1c2d3e4f56'
down_revision = '5b0118c4db82'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('scoped_access_code', schema=None) as batch_op:
        batch_op.add_column(sa.Column('custom_slug', sa.String(length=64), nullable=True))
        batch_op.create_unique_constraint('uq_scoped_access_code_custom_slug', ['custom_slug'])


def downgrade():
    with op.batch_alter_table('scoped_access_code', schema=None) as batch_op:
        batch_op.drop_constraint('uq_scoped_access_code_custom_slug', type_='unique')
        batch_op.drop_column('custom_slug')