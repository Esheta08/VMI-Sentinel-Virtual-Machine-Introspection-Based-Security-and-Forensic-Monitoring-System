import uuid
from datetime import datetime

from collector.event_model import VMEvent


def test_vm_event_creation():
    event = VMEvent(
        event_id=str(uuid.uuid4()),
        vm_name="test-vm",
        event_type="PROCESS_CREATED",
        timestamp=datetime.now(),
        process_id=1523,
        parent_process_id=821,
        process_name="bash",
        description="Test process event",
    )

    assert event.vm_name == "test-vm"
    assert event.event_type == "PROCESS_CREATED"
    assert event.process_id == 1523
    assert event.description == "Test process event"
