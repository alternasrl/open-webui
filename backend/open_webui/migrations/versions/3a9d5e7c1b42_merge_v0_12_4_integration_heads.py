"""merge v0.12.4 upstream and fork heads

Revision ID: 3a9d5e7c1b42
Revises: 0bd252b206fb, e304e2e7c45a
Create Date: 2026-10-28 15:20:00.000000

"""

from typing import Sequence, Union

# revision identifiers, used by Alembic.
revision: str = '3a9d5e7c1b42'
down_revision: Union[str, Sequence[str], None] = ('0bd252b206fb', 'e304e2e7c45a')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
