import uuid
from datetime import datetime, timezone

from collector.event_model import VMEvent
from processor.event_pipeline import EventPipeline


def test_event_pipeline_stores_event():
    event = VMEvent(
        event_id=str(uuid.uuid4()),
        vm_name="test-vm",
        event_type="PROCESS_CREATED",
        timestamp=datetime.now(timezone.utc),
        process_id=2456,
        parent_process_id=1000,
        process_name="python3",
        memory_address=None,
        memory_size=None,
        description="End-to-end pipeline test",
    )

    pipeline = EventPipeline()
    inserted = pipeline.handle_event(event)

    assert inserted is True
