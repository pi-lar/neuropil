# SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

# generated by datamodel-codegen:
#   filename:  flavor.schema.json
#   timestamp: 2024-08-29T09:54:13+00:00

from __future__ import annotations

from typing import Annotated, List, Optional

from pydantic import BaseModel, Field, StringConstraints

from .network_intent import NetworkIntentSchema


class Gpu(BaseModel):
    model: Optional[str] = Field(
        None, description="The model of the GPU offered for the specific Flavor."
    )
    cores: Optional[
        Annotated[
            str, StringConstraints(pattern=r"^[0-9]+(m|([.][0-9]+)?|[kMGTP]i?)?$")
        ]
    ] = Field(None, description="The number of GPU cores advertised by the Flavor.")
    memory: Optional[
        Annotated[
            str, StringConstraints(pattern=r"^[0-9]+(Ki|Mi|Gi|Ti|Pi|Ei|k|M|G|T|P|E)?$")
        ]
    ] = Field(None, description="The amount of GPU memory advertised by the Flavor.")


class Characteristics(BaseModel):
    architecture: Optional[str] = Field(
        None, description="The architecture of the Flavor (e.g., x86, ARM)."
    )
    cpu: Annotated[
        str, StringConstraints(pattern=r"^[0-9]+(m|([.][0-9]+)?|[kMGTP]i?)?$")
    ] = Field(..., description="The number of CPU cores")
    pods: Annotated[str, StringConstraints(pattern=r"^[0-9]+$")] = Field(
        ..., description="The number of pods"
    )
    memory: Annotated[
        str, StringConstraints(pattern=r"^[0-9]+(Ki|Mi|Gi|Ti|Pi|Ei|k|M|G|T|P|E)?$")
    ] = Field(..., description="The amount of memory")
    gpu: Optional[Gpu] = Field(None, description="GPU characteristics of the Flavor.")
    storage: Optional[
        Annotated[
            str, StringConstraints(pattern=r"^[0-9]+(Ki|Mi|Gi|Ti|Pi|Ei|k|M|G|T|P|E)?$")
        ]
    ] = Field(None, description="The amount of storage")


class CarbonFootprint(BaseModel):
    embodied: Optional[int] = Field(
        None,
        description="Embodied carbon of the node hardware normalized by its expected lifetime.",
    )
    operational: Optional[List] = Field(
        None,
        description="Forecasted average carbon intensity of the node for the next N windows/hours.",
    )


class Partitionability(BaseModel):
    cpuMin: Optional[
        Annotated[
            str, StringConstraints(pattern=r"^[0-9]+(m|([.][0-9]+)?|[kMGTP]i?)?$")
        ]
    ] = Field(
        None,
        description="Minimum required number of CPU cores of the Flavor for the eventual partition.",
    )
    memoryMin: Optional[
        Annotated[
            str, StringConstraints(pattern=r"^[0-9]+(Ki|Mi|Gi|Ti|Pi|Ei|k|M|G|T|P|E)?$")
        ]
    ] = Field(
        None,
        description="Minimum required amount of RAM of the Flavor for the eventual partition.",
    )
    podsMin: Optional[Annotated[str, StringConstraints(pattern=r"^[0-9]+$")]] = Field(
        None,
        description="Minimum required number of pods of the Flavor for the eventual partition.",
    )
    cpuStep: Optional[
        Annotated[
            str, StringConstraints(pattern=r"^[0-9]+(m|([.][0-9]+)?|[kMGTP]i?)?$")
        ]
    ] = Field(
        None,
        description="Incremental value of CPU cores of the Flavor for the eventual partition.",
    )
    memoryStep: Optional[
        Annotated[
            str, StringConstraints(pattern=r"^[0-9]+(Ki|Mi|Gi|Ti|Pi|Ei|k|M|G|T|P|E)?$")
        ]
    ] = Field(
        None,
        description="Incremental value of RAM of the Flavor for the eventual partition.",
    )
    podsStep: Optional[Annotated[str, StringConstraints(pattern=r"^[0-9]+$")]] = Field(
        None,
        description="Incremental value of pods of the Flavor for the eventual partition.",
    )


class Policies(BaseModel):
    partitionability: Optional[Partitionability] = None


class NetworkAuthorizations(BaseModel):
    deniedCommunications: Optional[List[NetworkIntentSchema]] = Field(
        None, description="List of denied communication."
    )
    mandatoryCommunications: Optional[List[NetworkIntentSchema]] = Field(
        None, description="List of mandatory communication (e.g., monitoring)."
    )


class Properties(BaseModel):
    latency: Optional[int] = Field(
        None, description="The latency of the Flavor in milliseconds."
    )
    securityStandards: Optional[List[str]] = Field(
        None, description="Security standards supported by the Flavor (e.g., GDPR)."
    )
    carbonFootprint: Optional[CarbonFootprint] = None
    networkAuthorizations: Optional[NetworkAuthorizations] = Field(
        None, description="Network authorizations of the Flavor."
    )


class K8SliceSchema(BaseModel):
    characteristics: Characteristics
    properties: Properties
    policies: Policies
