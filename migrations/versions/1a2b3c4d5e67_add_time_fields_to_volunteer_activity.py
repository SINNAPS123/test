"""add time fields to volunteer_activity

Revision ID: 1a2b3c4d5e67
Revises: 9a1c2d3e4f56
Create Date: 2025-09-16 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1a2b3c4d5e67'
down_revision = '9a1c2d3e4f56'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('volunteer_activity') as batch_op:
        batch_op.add_column(sa.Column('start_time', sa.Time(), nullable=True))
        batch_op.add_column(sa.Column('end_time', sa.Time(), nullable=True))


def downgrade():
    with op.batch_alter_table('volunteer_activity') as batch_op:
        batch_op.drop_column('end_time')
        batch_op.drop_column('start_time')