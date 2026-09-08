"""merge v0.11.3 integration heads

Revision ID: 28f62ff35ad1
Revises: d4c1a8e37b62, f8a9b0c1d2e3
Create Date: 2026-09-09 01:21:49.353958

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import open_webui.internal.db


# revision identifiers, used by Alembic.
revision: str = '28f62ff35ad1'
down_revision: Union[str, None] = ('d4c1a8e37b62', 'f8a9b0c1d2e3')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
