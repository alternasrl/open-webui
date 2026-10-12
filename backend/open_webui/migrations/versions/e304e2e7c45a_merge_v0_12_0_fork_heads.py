"""merge v0.12.0 fork heads

Revision ID: e304e2e7c45a
Revises: 6c7d8e9f0a1b, b8f2c6d91a04
Create Date: 2026-10-12 16:06:34.396196

"""

from typing import Sequence, Union

# revision identifiers, used by Alembic.
revision: str = 'e304e2e7c45a'
down_revision: Union[str, Sequence[str], None] = ('6c7d8e9f0a1b', 'b8f2c6d91a04')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
