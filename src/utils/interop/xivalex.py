import dataclasses
import ipaddress
import json
import logging
import os
import time
import typing
import urllib.request

from utils.consts import OPCODE_DEFINITION_LIST_URL


@dataclasses.dataclass
class OpcodeDefinition:
    Name: str
    C2S_ActionRequest: int
    C2S_ActionRequestGroundTargeted: int
    S2C_ActionEffect01: int
    S2C_ActionEffect08: int
    S2C_ActionEffect16: int
    S2C_ActionEffect24: int
    S2C_ActionEffect32: int
    S2C_ActorCast: int
    S2C_ActorControl: int
    S2C_ActorControlSelf: int
    Common_UseOodleTcp: bool
    Server_IpRange: list[
        ipaddress.IPv4Network |
        ipaddress.IPv6Network |
        tuple[ipaddress.IPv4Address, ipaddress.IPv4Address] |
        tuple[ipaddress.IPv6Address, ipaddress.IPv6Address]
    ]
    Server_PortRange: list[tuple[int, int]]

    @classmethod
    def from_dict(cls, data: dict):
        kwargs = {}
        for field in dataclasses.fields(cls):
            field: dataclasses.Field
            if field.type is int:
                kwargs[field.name] = int(data[field.name], 0)
            elif field.name == "Server_IpRange":
                iplist = []
                for partstr in data[field.name].split(","):
                    part = [x.strip() for x in partstr.split("-")]
                    try:
                        if len(part) == 1:
                            iplist.append(ipaddress.ip_network(part[0], False))
                        elif len(part) == 2:
                            iplist.append(tuple(sorted(ipaddress.ip_address(x) for x in part)))
                        else:
                            raise ValueError
                    except ValueError:
                        print("Skipping invalid IP address definition", partstr)
                kwargs[field.name] = iplist
            elif field.name == "Server_PortRange":
                portlist = []
                for partstr in data[field.name].split(","):
                    part = [x.strip() for x in partstr.split("-")]
                    try:
                        if len(part) == 1:
                            portlist.append((int(part[0], 0), int(part[0], 0)))
                        elif len(part) == 2:
                            portlist.append((int(part[0], 0), int(part[1], 0)))
                        else:
                            raise ValueError
                    except ValueError:
                        print("Skipping invalid port definition", partstr)
                kwargs[field.name] = portlist
            else:
                kwargs[field.name] = None if data[field.name] is None else field.type(data[field.name])
        return OpcodeDefinition(**kwargs)

    def is_applicable(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int):
        return any(ip in x for x in self.Server_IpRange) and any(x[0] <= port <= x[1] for x in self.Server_PortRange)

    def is_action_effect(self, opcode: int):
        return (opcode == self.S2C_ActionEffect01
                or opcode == self.S2C_ActionEffect08
                or opcode == self.S2C_ActionEffect16
                or opcode == self.S2C_ActionEffect24
                or opcode == self.S2C_ActionEffect32)


@dataclasses.dataclass(frozen=True)
class MitigationConfig:
    measure_ping: bool
    extra_delay: float
    definitions: list[OpcodeDefinition]


def load_definitions(root_path: str, update_opcodes: bool, json_path: str | None) -> list[OpcodeDefinition]:
    if json_path is not None and json_path.strip() != "":
        with open(json_path) as fp:
            return [OpcodeDefinition.from_dict({"Name": json_path, **json.load(fp)})]

    definitions_filepath = os.path.join(root_path, "definitions.json")
    if os.path.exists(definitions_filepath):
        try:
            if update_opcodes:
                raise RuntimeError("Force update requested")
            if os.path.getmtime(definitions_filepath) + 60 * 60 < time.time():
                raise RuntimeError("Definitions file older than an hour")
            with open(definitions_filepath, "r") as fp:
                return [OpcodeDefinition.from_dict(x) for x in json.load(fp)]
        except Exception as e:
            logging.info(f"Failed to read previous opcode definition files: {e}")

    definitions_raw = []
    logging.info("Downloading opcode definition files...")
    try:
        with urllib.request.urlopen(OPCODE_DEFINITION_LIST_URL) as resp:
            filelist = json.load(resp)

        for f in filelist:
            if f["name"][-5:].lower() != '.json':
                continue
            with urllib.request.urlopen(f["download_url"]) as resp:
                data = json.load(resp)
            data["Name"] = f["name"]
            definitions_raw.append(data)
    except Exception as e:
        raise RuntimeError(f"Failed to load opcode definition") from e
    with open(definitions_filepath, "w") as fp:
        json.dump(definitions_raw, fp)
    definitions = [OpcodeDefinition.from_dict(x) for x in definitions_raw]
    return definitions
