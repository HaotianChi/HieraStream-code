"""Logical actors for the journal protocol (one-host research prototype).

Trust / data boundaries are preserved in code even when colocated:
  CA, AA, RM, OwnerGateway, OutsourceService, DataUser, FabricClient, IPFSClient
"""

from core.actors.authorities import AttributeAuthority, CentralAuthority, RoleManager
from core.actors.gateway import OwnerGateway
from core.actors.outsource import OutsourceService
from core.actors.users import DataUser

__all__ = [
    "CentralAuthority",
    "AttributeAuthority",
    "RoleManager",
    "OwnerGateway",
    "OutsourceService",
    "DataUser",
]
