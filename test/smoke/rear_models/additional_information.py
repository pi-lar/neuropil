# SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class AdditionalInformation(BaseModel):
    LiqoID: Optional[str] = Field(None, description="Liqo ID of the node.")
    np_bootstrap_address: Optional[str] = Field(
        None,
        description="np:// bootstrap address to join a set of connected fluidos clusters",
    )
