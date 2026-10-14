from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class VMEvent:
    event_id: str
    vm_name: str
    event_type: str
    timestamp: datetime

    process_id: Optional[int] = None
    parent_process_id: Optional[int] = None
    process_name: Optional[str] = None

    memory_address: Optional[str] = None
    memory_size: Optional[int] = None

    description: Optional[str] = None