"""create users table

Revision ID: 001_create_users_table
Revises:
Create Date: 2026-03-27
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "001_create_users_table"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("password", sa.String(), nullable=False, unique=True),
    )
    op.create_index(op.f("ix_users_username"), "users", ["username"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_users_username"), table_name="users")
    op.drop_table("users")
