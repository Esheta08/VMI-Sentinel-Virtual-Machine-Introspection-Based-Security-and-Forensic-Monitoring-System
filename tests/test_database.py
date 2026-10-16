import uuid
from datetime import datetime, timezone

from collector.event_model import VMEvent
from processor.event_processor import EventProcessor
from database.database import insert_event


event = VMEvent(
    event_id=str(uuid.uuid4()),
    vm_name="test-vm",
    event_type="PROCESS_CREATED",
    timestamp=datetime.now(timezone.utc),
    process_id=1523,
    parent_process_id=821,
    process_name="bash",
    memory_address=None,
    memory_size=None,
    description="Database integration test",
)

processed_event = EventProcessor().process(event)

inserted = insert_event(processed_event)

if inserted:
    print("Event inserted successfully!")
else:
    print("Event already exists; duplicate skipped.")