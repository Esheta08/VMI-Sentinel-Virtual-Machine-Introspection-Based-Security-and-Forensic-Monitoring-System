from collector.event_model import VMEvent
from processor.event_processor import EventProcessor
from database.database import insert_event


class EventPipeline:
    """Process VM events and store them in PostgreSQL."""

    def __init__(self):
        self.processor = EventProcessor()

    def handle_event(self, event: VMEvent) -> bool:
        """Process an event and store it in the database."""

        processed_event = self.processor.process(event)

        return insert_event(processed_event)